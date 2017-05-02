#ifndef CLICK_BSDIPLOOKUP_HH
#define CLICK_BSDIPLOOKUP_HH
#include "iproutetable.hh"
CLICK_DECLS

/*
=c

BSDIPLookup(ADDR1/MASK1 [GW1] OUT1, ADDR2/MASK2 [GW2] OUT2, ...)

=s iproute

IP routing lookup using a variant of PATRICIA trie

=d

Expects a destination IP address annotation with each packet. Looks up that
address in its routing table, using longest-prefix-match, sets the destination
annotation to the corresponding GW (if specified), and emits the packet on the
indicated OUTput port.

Each argument is a route, specifying a destination and mask, an optional
gateway IP address, and an output port.  No destination-mask pair may
occur more than once.

Uses the IPRouteTable interface; see IPRouteTable for description.

BSDIPLookup is optimized for fast database updates, while longest-prefix
lookups are accomplished in at most O(W) time, where W is the width
of the search key.  The implementation is based on the historic
I<PATRICIA trie> lookup scheme borrowed from FreeBSD, described by Keith
Sklower in the paper cited below.

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

=a IPRouteTable, DirectIPLookup, DXRIPLookup, StaticIPLookup,
LinearIPLookup, SortedIPLookup, LinuxIPLookup

Keith Sklower.  "A tree-based packet routing table for Berkeley UNIX".
In Proc. USENIX Winter 1991 Technical Conference, pp. 93-104.

*/

extern "C" {
/* From FreeBSD: net/radix.h */
/*-
 * Copyright (c) 1988, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)radix.h	8.2 (Berkeley) 10/31/94
 * $FreeBSD: release/9.2.0/sys/net/radix.h 225698 2011-09-20 20:27:26Z kmacy $
 */

#ifndef _RADIX_H_
#define	_RADIX_H_

#ifdef _KERNEL
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/_rwlock.h>
#endif

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_RTABLE);
#endif

/*
 * Radix search tree node layout.
 */

struct radix_node {
	struct	radix_mask *rn_mklist;	/* list of masks contained in subtree */
	struct	radix_node *rn_parent;	/* parent */
	short	rn_bit;			/* bit offset; -1-index(netmask) */
	char	rn_bmask;		/* node: mask for bit test*/
	u_char	rn_flags;		/* enumerated next */
#define RNF_NORMAL	1		/* leaf contains normal route */
#define RNF_ROOT	2		/* leaf is root leaf for tree */
#define RNF_ACTIVE	4		/* This node is alive (for rtfree) */
	union {
		struct {			/* leaf only data: */
			caddr_t	rn_Key;		/* object of search */
			caddr_t	rn_Mask;	/* netmask, if present */
			struct	radix_node *rn_Dupedkey;
		} rn_leaf;
		struct {			/* node only data: */
			int	rn_Off;		/* where to start compare */
			struct	radix_node *rn_L;/* progeny */
			struct	radix_node *rn_R;/* progeny */
		} rn_node;
	}		rn_u;
#ifdef RN_DEBUG
	int rn_info;
	struct radix_node *rn_twin;
	struct radix_node *rn_ybro;
#endif
};

#define	rn_dupedkey	rn_u.rn_leaf.rn_Dupedkey
#define	rn_key		rn_u.rn_leaf.rn_Key
#define	rn_mask		rn_u.rn_leaf.rn_Mask
#define	rn_offset	rn_u.rn_node.rn_Off
#define	rn_left		rn_u.rn_node.rn_L
#define	rn_right	rn_u.rn_node.rn_R

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

struct radix_mask {
	short	rm_bit;			/* bit offset; -1-index(netmask) */
	char	rm_unused;		/* cf. rn_bmask */
	u_char	rm_flags;		/* cf. rn_flags */
	struct	radix_mask *rm_mklist;	/* more masks to try */
	union	{
		caddr_t	rmu_mask;		/* the mask */
		struct	radix_node *rmu_leaf;	/* for normal routes */
	}	rm_rmu;
	int	rm_refs;		/* # of references to this struct */
};

#define	rm_mask rm_rmu.rmu_mask
#define	rm_leaf rm_rmu.rmu_leaf		/* extra field would make 32 bytes */

typedef int walktree_f_t(struct radix_node *, void *);

struct radix_node_head {
	struct	radix_node *rnh_treetop;
	u_int	rnh_gen;		/* generation counter */
	int	rnh_multipath;		/* multipath capable ? */
	int	rnh_addrsize;		/* permit, but not require fixed keys */
	int	rnh_pktsize;		/* permit, but not require fixed keys */
	struct	radix_node *(*rnh_addaddr)	/* add based on sockaddr */
		(void *v, void *mask,
		     struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_addpkt)	/* add based on packet hdr */
		(void *v, void *mask,
		     struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_deladdr)	/* remove based on sockaddr */
		(void *v, void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_delpkt)	/* remove based on packet hdr */
		(void *v, void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_matchaddr)	/* locate based on sockaddr */
		(void *v, struct radix_node_head *head);
	struct	radix_node *(*rnh_lookup)	/* locate based on sockaddr */
		(void *v, void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_matchpkt)	/* locate based on packet hdr */
		(void *v, struct radix_node_head *head);
	int	(*rnh_walktree)			/* traverse tree */
		(struct radix_node_head *head, walktree_f_t *f, void *w);
	int	(*rnh_walktree_from)		/* traverse tree below a */
		(struct radix_node_head *head, void *a, void *m,
		     walktree_f_t *f, void *w);
	void	(*rnh_close)	/* do something when the last ref drops */
		(struct radix_node *rn, struct radix_node_head *head);
	struct	radix_node rnh_nodes[3];	/* empty tree for common case */
#ifdef _KERNEL
	struct	rwlock rnh_lock;		/* locks entire radix tree */
#endif
};

#ifndef _KERNEL
#define R_Malloc(p, t, n) (p = (t) malloc((unsigned int)(n)))
#define R_Zalloc(p, t, n) (p = (t) calloc(1,(unsigned int)(n)))
#define Free(p) free((char *)p);
#else
#define R_Malloc(p, t, n) (p = (t) malloc((unsigned long)(n), M_RTABLE, M_NOWAIT))
#define R_Zalloc(p, t, n) (p = (t) malloc((unsigned long)(n), M_RTABLE, M_NOWAIT | M_ZERO))
#define Free(p) free((caddr_t)p, M_RTABLE);

#define	RADIX_NODE_HEAD_LOCK_INIT(rnh)	\
    rw_init_flags(&(rnh)->rnh_lock, "radix node head", 0)
#define	RADIX_NODE_HEAD_LOCK(rnh)	rw_wlock(&(rnh)->rnh_lock)
#define	RADIX_NODE_HEAD_UNLOCK(rnh)	rw_wunlock(&(rnh)->rnh_lock)
#define	RADIX_NODE_HEAD_RLOCK(rnh)	rw_rlock(&(rnh)->rnh_lock)
#define	RADIX_NODE_HEAD_RUNLOCK(rnh)	rw_runlock(&(rnh)->rnh_lock)
#define	RADIX_NODE_HEAD_LOCK_TRY_UPGRADE(rnh)	rw_try_upgrade(&(rnh)->rnh_lock)


#define	RADIX_NODE_HEAD_DESTROY(rnh)	rw_destroy(&(rnh)->rnh_lock)
#define	RADIX_NODE_HEAD_LOCK_ASSERT(rnh) rw_assert(&(rnh)->rnh_lock, RA_LOCKED)
#define	RADIX_NODE_HEAD_WLOCK_ASSERT(rnh) rw_assert(&(rnh)->rnh_lock, RA_WLOCKED)
#endif /* _KERNEL */

void	 rn_init(int);
int	 rn_inithead(void **, int);
int	 rn_detachhead(void **);
int	 rn_refines(void *, void *);
struct radix_node
	 *rn_addmask(void *, int, int),
	 *rn_addroute (void *, void *, struct radix_node_head *,
			struct radix_node [2]),
	 *rn_delete(void *, void *, struct radix_node_head *),
	 *rn_lookup (void *v_arg, void *m_arg,
		        struct radix_node_head *head),
	 *rn_match(void *, struct radix_node_head *);

#endif /* _RADIX_H_ */
} /* extern "C" */


struct sockaddr_ip4 {
	uint8_t		sac_len;
	uint32_t	sac_addr;
};

struct sockaddr_ip6 {
	uint8_t		sac_len;
	uint32_t	sac_addr[4];
};

/*
 * XXX struct rtentry must begin with a struct radix_node (or two!)
 * because the code does some casts of a 'struct radix_node *'
 * to a 'struct rtentry *'
 */
#define	rt_key(r) (*((struct sockaddr **)(void *)(&(r)->rt_nodes->rn_key)))
#define	rt_mask(r) (*((struct sockaddr **)(void *)(&(r)->rt_nodes->rn_mask)))

struct rtentry4 {
	struct radix_node	rt_nodes[2]; /* tree glue, and other values */
	struct sockaddr_ip4	dst;
	uint32_t		nh;	/* index in nexthop table */
};

struct rtentry6 {
	struct radix_node	rt_nodes[2]; /* tree glue, and other values */
	struct sockaddr_ip6	dst;
	uint32_t		nh;	/* index in nexthop table */
};

struct nexthop4 {
	IPAddress	gw;
	int32_t		port;
	int32_t		refcount;
	int16_t		ll_next;
	int16_t		ll_prev;
};


#define	VPORTS_MAX	8192
#define	NH2GW(nh)	_nexthop_tbl[nh].gw
#define	NH2PORT(nh)	_nexthop_tbl[nh].port


class BSDIPLookup : public IPRouteTable {
    public:
	BSDIPLookup();
	~BSDIPLookup();

	const char *class_name() const	{ return "BSDIPLookup"; }
	const char *port_count() const	{ return "-/-"; }
	const char *processing() const	{ return PUSH; }

	void add_handlers();

	int add_route(const IPRoute&, bool, IPRoute*, ErrorHandler *);
	int remove_route(const IPRoute&, IPRoute*, ErrorHandler *);
	int lookup_route(IPAddress, IPAddress&) const;
	String dump_routes();

	/* Called from pure C, so needs to be public */
	void flush_walk(struct radix_node *);

    protected:
	int lookup_nexthop(uint32_t) const;
	int nexthop_ref(IPAddress, int);
	int nexthop_unref(int);
	void flush_table();
	static int flush_handler(const String &, Element *, void *,
	    ErrorHandler *);
	static String status_handler(Element *, void *);

	struct radix_node_head *_ip_rnh;
	struct nexthop4 *_nexthop_tbl;
	int _prefix_cnt;
	int _nexthops;
	int _nexthop_tbl_size;
	int _nexthop_head;
	int _nexthop_empty_head;
};

CLICK_ENDDECLS
#endif
