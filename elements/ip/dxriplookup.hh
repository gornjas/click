#ifndef CLICK_DXRIPLOOKUP_HH
#define CLICK_DXRIPLOOKUP_HH
#include "bsdiplookup.hh"
#include <click/timer.hh>

#include <pthread.h>

extern "C" {
#include <sys/queue.h>
}

CLICK_DECLS

/*
=c

DXRIPLookup(ADDR1/MASK1 [GW1] OUT1, ADDR2/MASK2 [GW2] OUT2, ...)

=s iproute

IP routing lookup through binary search in compact lookup tables

=d

Expects a destination IP address annotation with each packet. Looks up that
address in its routing table, using longest-prefix-match, sets the destination
annotation to the corresponding GW (if specified), and emits the packet on the
indicated OUTput port.

Each argument is a route, specifying a destination and mask, an optional
gateway IP address, and an output port.  No destination-mask pair may
occur more than once.

Uses the IPRouteTable interface; see IPRouteTable for description.

DXRIPLookup aims at achieving high lookup speeds through exploiting
the CPU cache locality.  The routing table is expanded into a very
small lookup  structure, typically occupying less than 4 bytes per IP
prefix for large BGP views, which permits the lookup structures to easily
fit in cache hierarchy of contemporary CPU cores.  The algorithm is
presented in detail in the paper cited below.

DXRIPLookup maintains a BSDIPLookup backend database as well as its
own auxiliary tables, which permit incremental lookup table updates
to be performed at high speeds.  Although those subsidiary tables are only
accessed during route updates, they significantly add to DXRIPLookup's
total memory footprint.


=h table read-only

Outputs a human-readable version of the current routing table.

=h lookup read-only

Reports the OUTput port and GW corresponding to an address.

=h add write-only

Adds a route to the table.  Format should be `C<ADDR/MASK [GW] OUT>'.
Fails if a route for C<ADDR/MASK> already exists.

=h set write-only

Sets a route, whether or not a route for the same prefix already exists.

=h remove write-only

Removes a route from the table.  Format should be `C<ADDR/MASK>'.

=h ctrl write-only

Adds or removes a group of routes. Write `C<add>/C<set ADDR/MASK [GW] OUT>' to
add a route, and `C<remove ADDR/MASK>' to remove a route. You can supply
multiple commands, one per line; all commands are executed as one atomic
operation.

=h flush write-only

Clears the entire routing table in a single atomic operation.

=h stat read-only

Outputs human-readable report on current database state.

=n

See IPRouteTable for a performance comparison of the various IP routing
elements.

=a IPRouteTable, BSDIPLookup, DirectIPLookup, StaticIPLookup,
LinearIPLookup, SortedIPLookup, LinuxIPLookup

Marko Zec, Luigi Rizzo, Miljenko Mikuc.  "DXR: Towards a Billion Routing
Lookups per Second in Software".  ACM Computer Communication Review,
Vol. 42(5), 2012, pp. 29-36.

*/

/* D20R is the default sweetspot configuration */
#ifndef DXR_DIRECT_BITS
#define	DXR_DIRECT_BITS 20
#endif

#define	DIRECT_TBL_SIZE	(1 << DXR_DIRECT_BITS)
#define	DXR_RANGE_MASK	(0xffffffff >> DXR_DIRECT_BITS)
#define	DXR_RANGE_SHIFT	(32 - DXR_DIRECT_BITS)

#define	DESC_BASE_BITS	19
#define	BASE_MAX	((1 << DESC_BASE_BITS) - 1)
#define	FRAG_BITS	(31 - DESC_BASE_BITS)
#define	LONG_FORMAT_BIT	(1 << FRAG_BITS)
#define	FRAG_MAX	(LONG_FORMAT_BIT - 1)

#define	CHUNK_HASH_BITS 16
#define	CHUNK_HASH_SIZE (1 << CHUNK_HASH_BITS)
#define	CHUNK_HASH_MASK (CHUNK_HASH_SIZE - 1)


class DXRIPLookup : public BSDIPLookup {
    public:
	DXRIPLookup();
	~DXRIPLookup();

	const char *class_name() const { return "DXRIPLookup"; }
	const char *port_count() const { return "-/-"; }
	const char *processing() const { return PUSH; }

	int initialize(ErrorHandler *);
	void add_handlers();

	int add_route(const IPRoute&, bool, IPRoute*, ErrorHandler *);
	int remove_route(const IPRoute&, IPRoute*, ErrorHandler *);
	int lookup_route(IPAddress, IPAddress &) const;

	void run_timer(Timer *);

	/* Called from pure C, so those two need to be public */
	int dxr_walk(struct radix_node *, uint32_t);
	int dxr_walk_long(struct radix_node *, uint32_t);
	void bench_thread(void *);

    protected:

	struct range_entry_long {
#if (DXR_DIRECT_BITS < 14)
		uint32_t start;
		uint32_t nexthop;
#elif (DXR_DIRECT_BITS < 16)
		uint32_t
			nexthop:DXR_DIRECT_BITS,
			start:DXR_RANGE_SHIFT;
#else
		uint16_t nexthop;
		uint16_t start;
#endif
	};

	struct range_entry_short {
		uint8_t nexthop;
		uint8_t start;
	};

	struct direct_entry {
		uint32_t
			fragments:FRAG_BITS,
			long_format:1,
			base:DESC_BASE_BITS;
	};

	struct dxr_heap_entry {
		uint32_t start;
		uint32_t end;
		uint16_t preflen;
		uint16_t nexthop;
	};

	struct chunk_desc {
		LIST_ENTRY(chunk_desc)	cd_all_le;
		LIST_ENTRY(chunk_desc)	cd_hash_le;
		uint32_t		cd_hash;
		uint32_t		cd_refcount;
		uint32_t		cd_base;
		uint32_t		cd_cur_size;
		uint32_t		cd_max_size;
		int32_t			cd_chunk_first;
	};

	struct chunk_ptr {
		struct chunk_desc	*cp_cdp;
		int32_t			cp_chunk_next;
	};

	LIST_HEAD(chunk_list_head, chunk_desc);


	/* Lookup structures */
	struct direct_entry *_direct_tbl;
	struct range_entry_long *_range_tbl;

	/* Auxiliary structures */
	struct chunk_ptr *_cptbl;
	chunk_list_head *_chunk_hashtbl;
	chunk_list_head _all_chunks;
	chunk_list_head _unused_chunks;
	struct dxr_heap_entry _dxr_heap[33];
	int _heap_index;
	int _range_tbl_free;
	int _chunks_short;
	int _chunks_long;
	int _fragments_short;
	int _fragments_long;
	int _aggr_chunks_short;
	int _aggr_chunks_long;
	int _aggr_fragments_short;
	int _aggr_fragments_long;

	int _updates_pending;
	uint32_t *_pending_bitmask;
	uint32_t _pending_start;
	uint32_t _pending_end;
	uint32_t _last_update_us;
	Timer _update_scanner;

	int _bench_sel;
	int _bench_threads;
	int _skip_smt;
	int _ncpus;
	size_t _test_blk;
	uint32_t *_key_tbl;
	uint16_t *_nh_tbl;

	int lookup_nexthop(uint32_t) const;
	void schedule_update(const IPRoute &);
	void apply_pending(void);
	void update_chunk(uint32_t);
	void update_chunk_long(uint32_t);
	void dxr_initheap(uint32_t);
	void dxr_heap_inject(uint32_t, uint32_t, int, int);
	void prune_empty_chunks(void);
	uint32_t chunk_hash(struct direct_entry *);
	void chunk_ref(uint32_t);
	void chunk_unref(uint32_t);
	void flush_table();
	static int flush_handler(const String &, Element *, void *,
	    ErrorHandler *);
	static String status_handler(Element *, void *);
	static String bench_handler(Element *, void *);
	static int bench_select(const String &, Element *, void *, 
	    ErrorHandler *);
	static int thread_select(const String &, Element *, void *,
	    ErrorHandler *);
	static int skip_smt(const String &, Element *, void *,
	    ErrorHandler *);
	static int prepare_handler(const String &, Element *, void *,
	    ErrorHandler *);
	void bench_seq(uint32_t *, uint16_t *, uint32_t);
	void bench_rnd(uint32_t *, uint16_t *, uint32_t);
	void bench_rep(uint32_t *, uint16_t *, uint32_t);
	String status();
};

CLICK_ENDDECLS
#endif
