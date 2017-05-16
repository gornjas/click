// -*- c-basic-offset: 4 -*-
#ifndef CLICK_DIRECTIPLOOKUP_HH
#define CLICK_DIRECTIPLOOKUP_HH
#include "bsdiplookup.hh"
#include <click/timer.hh>

#include <pthread.h>

CLICK_DECLS

/*
=c

DirectIPLookup(ADDR1/MASK1 [GW1] OUT1, ADDR2/MASK2 [GW2] OUT2, ...)

=s iproute

IP routing lookup using direct-indexed tables

=d

Expects a destination IP address annotation with each packet. Looks up that
address in its routing table, using longest-prefix-match, sets the destination
annotation to the corresponding GW (if specified), and emits the packet on the
indicated OUTput port.

Each argument is a route, specifying a destination and mask, an optional
gateway IP address, and an output port.  No destination-mask pair should occur
more than once.

DirectIPLookup is optimized for lookup speed at the expense of extensive RAM
usage. Each longest-prefix lookup is accomplished in one to maximum two DRAM
accesses, regardless on the number of routing table entries. Individual
entries can be dynamically added to or removed from the routing table with
relatively low CPU overhead, allowing for high update rates.

DirectIPLookup implements the I<DIR-24-8-BASIC> lookup scheme described by
Gupta, Lin, and McKeown in the paper cited below.

=h table read-only

Outputs a human-readable version of the current routing table.

=h lookup read-only, requires parameters

Reports the OUTput port and GW corresponding to an address.

=h add write-only

Adds a route to the table. Format should be `C<ADDR/MASK [GW] OUT>'.
Fails if a route for C<ADDR/MASK> already exists.

=h set write-only

Sets a route, whether or not a route for the same prefix already exists.

=h remove write-only

Removes a route from the table. Format should be `C<ADDR/MASK>'.

=h ctrl write-only

Adds or removes a group of routes. Write `C<add>/C<set ADDR/MASK [GW] OUT>' to
add a route, and `C<remove ADDR/MASK>' to remove a route. You can supply
multiple commands, one per line; all commands are executed as one atomic
operation.

=h flush write-only

Clears the entire routing table in a single atomic operation.

=n

See IPRouteTable for a performance comparison of the various IP routing
elements.

DirectIPLookup's data structures are inherently limited: at most 2^15 /24
networks can contain routes for /25-or-smaller subnetworks, no matter how much
memory you have.  If you need more than this, try BSDIPLookup, DXRIPLookup
or RadixIPLookup.

=a IPRouteTable, BSDIPLookup, DXRIPLookup, RadixIPLookup, StaticIPLookup,
LinearIPLookup, SortedIPLookup, LinuxIPLookup

Pankaj Gupta, Steven Lin, and Nick McKeown.  "Routing Lookups in Hardware at
Memory Access Speeds".  In Proc. IEEE Infocom 1998, Vol. 3, pp. 1240-1247.

*/


#define	DIRECT_BITS 24
#define	SECONDARY_BITS (32 - DIRECT_BITS)
#define	PRIMARY_SIZE (1 << DIRECT_BITS)
#define	SECONDARY_SIZE ((1 << SECONDARY_BITS) * (1 << 15))
#define	SECONDARY_MASK ((1 << SECONDARY_BITS) - 1)

#define	DIR_CHUNK_PREFLEN 16
#define	DIR_CHUNKS	(1 << DIR_CHUNK_PREFLEN)
#define	DIR_CHUNK_SHIFT	(32 - DIR_CHUNK_PREFLEN)
#define	DIR_CHUNK_MASK	((1 << DIR_CHUNK_SHIFT) - 1)


class DirectIPLookup : public BSDIPLookup {
    public:
	DirectIPLookup();
	~DirectIPLookup();

	const char *class_name() const	{ return "DirectIPLookup"; }
	const char *port_count() const	{ return "-/-"; }
	const char *processing() const	{ return PUSH; }

	int initialize(ErrorHandler *);
	void add_handlers();

	int add_route(const IPRoute&, bool, IPRoute*, ErrorHandler *);
	int remove_route(const IPRoute&, IPRoute*, ErrorHandler *);
	int lookup_route(IPAddress, IPAddress&) const;

	void run_timer(Timer *);

	/* Called from pure C, so those two need to be public */
	int dir_walk(struct radix_node *, uint32_t);
	void bench_thread(void *);

    protected:

	struct dir_range_entry {
		uint32_t start;
		uint32_t nexthop;
	};

	struct dir_heap_entry {
		uint32_t start;
		uint32_t end;
		uint16_t preflen;
		uint16_t nexthop;
	};

	/* Lookup structures */
	uint16_t *_primary;
	uint16_t *_secondary;

	/* Auxiliary structures */
	struct dir_heap_entry _dir_heap[33];
	struct dir_range_entry *_range_buf;
	int _heap_index;
	uint32_t _range_fragments;
	uint32_t _secondary_used;
	uint32_t _secondary_free_head;

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
	volatile int _bench_active;
	size_t _test_blk;
	uint32_t *_key_tbl;
	uint16_t *_nh_tbl;

	int lookup_nexthop(uint32_t) const;
	void schedule_update(const IPRoute &);
	void apply_pending(void);
	void update_chunk(uint32_t);
	void dir_initheap(uint32_t);
	void dir_heap_inject(uint32_t, uint32_t, int, int);
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
	uint64_t bench_seq(uint32_t *, uint16_t *, uint32_t);
	uint64_t bench_rnd(uint32_t *, uint16_t *, uint32_t);
	uint64_t bench_rep(uint32_t *, uint16_t *, uint32_t);
	String status();
};

CLICK_ENDDECLS
#endif
