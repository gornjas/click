/*
 * dxriplookup.{cc,hh} -- binary search for output port and next-hop gateway
 * in a very compact sorted array, aiming for high CPU cache hit ratios
 * Marko Zec
 *
 * Copyright (c) 2005-2014 University of Zagreb
 * Copyright (c) 2005 International Computer Science Institute
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/straccum.hh>
#include "dxriplookup.hh"

#include <err.h>
#include <pthread_np.h>
#include <sysexits.h>
#include <unistd.h>

CLICK_DECLS


DXRIPLookup::DXRIPLookup()
	: _heap_index(0), _range_tbl_free(0),
	_chunks_short(0), _chunks_long(0), _fragments_short(0),
	_fragments_long(0), _aggr_chunks_short(0), _aggr_chunks_long(0),
	_aggr_fragments_short(0), _aggr_fragments_long(0),
	_updates_pending(0), _pending_start(DIRECT_TBL_SIZE),
	_pending_end(0), _update_scanner(this),
	_bench_sel(0), _bench_threads(1), _key_tbl(NULL), _nh_tbl(NULL)
{
	int i;

	LIST_INIT(&_all_chunks);
	LIST_INIT(&_unused_chunks);
	_direct_tbl = (struct direct_entry *)
	    CLICK_LALLOC(sizeof(*_direct_tbl) * DIRECT_TBL_SIZE);
	_range_tbl = (struct range_entry_long *)
	    CLICK_LALLOC(sizeof(*_range_tbl) * (BASE_MAX + 1));
	_pending_bitmask = (uint32_t *)
	    CLICK_LALLOC(sizeof(uint32_t) * (DIRECT_TBL_SIZE >> 5));
	_cptbl = (struct chunk_ptr *)
	    CLICK_LALLOC(sizeof(*_cptbl) * DIRECT_TBL_SIZE);
	_chunk_hashtbl = (chunk_list_head *)
	    CLICK_LALLOC(sizeof(*_chunk_hashtbl) * CHUNK_HASH_SIZE);
	assert(_direct_tbl != NULL);
	assert(_range_tbl != NULL);
	assert(_pending_bitmask != NULL);
	assert(_cptbl != NULL);
	assert(_chunk_hashtbl != NULL);

	for (i = 0; i < DIRECT_TBL_SIZE; i++) {
		_direct_tbl[i].base = 0;
		_direct_tbl[i].fragments = FRAG_MAX;
	}
	memset(_cptbl, 0, sizeof(*_cptbl) * DIRECT_TBL_SIZE);
	memset(_chunk_hashtbl, 0, sizeof(*_chunk_hashtbl) * CHUNK_HASH_SIZE);
	memset(_pending_bitmask, 0, sizeof(uint32_t) * (DIRECT_TBL_SIZE >> 5));
}


DXRIPLookup::~DXRIPLookup()
{

	flush_table();
	CLICK_LFREE(_chunk_hashtbl, sizeof(*_chunk_hashtbl) * CHUNK_HASH_SIZE);
	CLICK_LFREE(_cptbl, sizeof(*_cptbl) * DIRECT_TBL_SIZE);
	CLICK_LFREE(_pending_bitmask,
	    sizeof(*_pending_bitmask) * (DIRECT_TBL_SIZE >> 5));
	CLICK_LFREE(_range_tbl, sizeof(*_range_tbl) * (BASE_MAX + 1));
	CLICK_LFREE(_direct_tbl, sizeof(*_direct_tbl) * DIRECT_TBL_SIZE);
}


void
DXRIPLookup::add_handlers()
{
	IPRouteTable::add_handlers();
	add_write_handler("flush", flush_handler, 0, Handler::BUTTON);
	add_read_handler("stat", status_handler, 0, Handler::BUTTON);
	add_read_handler("bench", bench_handler, 0, Handler::BUTTON);
	add_write_handler("bench_sel", bench_select, 0, Handler::BUTTON);
	add_write_handler("prepare", prepare_handler, 0, Handler::BUTTON);
	add_write_handler("threads", thread_select, 0, Handler::BUTTON);
}


int
DXRIPLookup::initialize(ErrorHandler *)
{
	_update_scanner.initialize(this);
	if (_pending_start <= _pending_end)
		apply_pending();
	return (0);
}


void
DXRIPLookup::schedule_update(const IPRoute &r)
{
	uint32_t start, end, chunk;

	/* Default route change requires no updates to lookup structures */
	if (r.prefix_len() == 0)
		return;

	start = ntohl(r.addr.addr());
	end = start | ~ntohl(r.mask.addr());

	start = start >> DXR_RANGE_SHIFT;
	end = end >> DXR_RANGE_SHIFT;
	for (chunk = start; chunk <= end; chunk++)
		_pending_bitmask[chunk >> 5] |= (1 << (chunk & 0x1f));
	if (start < _pending_start)
		_pending_start = start;
	if (end > _pending_end)
		_pending_end = end;
	if (_updates_pending == 0 && _update_scanner.initialized())
		_update_scanner.schedule_after_msec(200);
	_updates_pending++;
}


void
DXRIPLookup::run_timer(Timer *)
{
	if (_updates_pending)
		apply_pending();
}


void
DXRIPLookup::apply_pending(void)
{
	uint32_t i, j, mask, bit, chunk;
	Timestamp t_start, t_len;

	t_start = Timestamp::now();
	for (i = _pending_start >> 5; i <= _pending_end >> 5; i++) {
		mask = _pending_bitmask[i];
		if (mask)
			for (j = 0, bit = 1; j < 32; j++) {
				if ((mask & bit)) {
					chunk = (i << 5) + j;
					update_chunk(chunk);
				}
				bit <<= 1;
			}
	}
	prune_empty_chunks();
	t_len = Timestamp::now() - t_start;
	_last_update_us = t_len.sec() * 1000000 + t_len.usec();

	_pending_start = DIRECT_TBL_SIZE;
	_pending_end = 0;
	_updates_pending = 0;
}


struct dxr_walk_arg {
	DXRIPLookup *obj;
	uint32_t chunk;
};


static int
dxr_walk_trampoline(struct radix_node *rn, void *arg)
{
	struct dxr_walk_arg *dwa = (struct dxr_walk_arg *) arg;

	return (dwa->obj->dxr_walk(rn, dwa->chunk));
}


static int
dxr_walk_long_trampoline(struct radix_node *rn, void *arg)
{
	struct dxr_walk_arg *dwa = (struct dxr_walk_arg *) arg;

	return (dwa->obj->dxr_walk_long(rn, dwa->chunk));
}


void
DXRIPLookup::dxr_heap_inject(uint32_t start, uint32_t end, int preflen, int nh)
{
	struct dxr_heap_entry *fhp;
	int i;

	for (i = _heap_index; i >= 0; i--) {
		if (preflen > _dxr_heap[i].preflen)
			break;
		else if (preflen < _dxr_heap[i].preflen) {
			bcopy(&_dxr_heap[i], &_dxr_heap[i+1],
			    sizeof(struct dxr_heap_entry));
		} else {
			/* Already the only item on heap, do nothing */
			assert(_heap_index == 0 &&
			    preflen == _dxr_heap[0].preflen &&
			    start == _dxr_heap[0].start &&
			    end == _dxr_heap[0].end &&
			    nh == _dxr_heap[0].nexthop);
			return;
		}
	}

	fhp = &_dxr_heap[i + 1];
	fhp->preflen = preflen;
	fhp->start = start;
	fhp->end = end;
	fhp->nexthop = nh;
	_heap_index++;
}


int
DXRIPLookup::dxr_walk(struct radix_node *rn, uint32_t chunk)
{
	struct rtentry4 *rt = (struct rtentry4 *)rn;
	struct sockaddr_ip4 *dst = (struct sockaddr_ip4 *)rt_key(rt);
	struct sockaddr_ip4 *mask = (struct sockaddr_ip4 *)rt_mask(rt);
	struct direct_entry *fdesc = &_direct_tbl[chunk];
	struct range_entry_short *fp = (struct range_entry_short *)
					&_range_tbl[fdesc->base] +
					fdesc->fragments;
	struct dxr_heap_entry *fhp = &_dxr_heap[_heap_index];
	uint32_t first = chunk << DXR_RANGE_SHIFT;
	uint32_t last = first | DXR_RANGE_MASK;
	uint32_t start, end;
	uint32_t preflen, nh;

	start = ntohl(dst->sac_addr);
	if (mask) {
		preflen = ffs(ntohl(mask->sac_addr));
		if (preflen)
			preflen = 33 - preflen;
		end = start | ~ntohl(mask->sac_addr);
	} else {
		preflen = 32;
		end = start;
	}
	if (start > last)
		return (-1);	/* Beyond chunk boundaries, we are done */
	if (start < first)
		return (0);	/* Skip this route */
	nh = rt->nh;

	/* Switch to long format if needed */
	if ((start & 0xff) || end < (start | 0xff) || nh > 0xff)
		return (ERANGE);

	if (start == fhp->start) {
		assert(preflen <= fhp->preflen);
		dxr_heap_inject(start, end, preflen, nh);
	} else if (start < fhp->start) {
		/* This MUST NEVER happen! */
		assert(start >= fhp->start);
	} else {
		/* start > fhp->start */
		while (start > fhp->end) {
			uint32_t oend = fhp->end;

			if (_heap_index > 0) {
				fhp--;
				_heap_index--;
			} else
				dxr_initheap(fhp->end + 1);
			if (fhp->end > oend && fhp->nexthop != fp->nexthop) {
				if (fhp->nexthop > 0xff)
					return (ERANGE);
				fp++;
				fdesc->fragments++;
				fp->start =
				    ((oend + 1) & DXR_RANGE_MASK) >> 8;
				fp->nexthop = fhp->nexthop;
			}
		}
		if (start > ((chunk << DXR_RANGE_SHIFT) | (fp->start << 8))
		    && nh != fp->nexthop) {
			fp++;
			fdesc->fragments++;
			fp->start = (start & DXR_RANGE_MASK) >> 8;
		} else if (fdesc->fragments) {
			if ((--fp)->nexthop == nh)
				fdesc->fragments--;
			else
				fp++;
		}
		fp->nexthop = nh;
		dxr_heap_inject(start, end, preflen, nh);
	}

	return (0);
}


int
DXRIPLookup::dxr_walk_long(struct radix_node *rn, uint32_t chunk)
{
	struct rtentry4 *rt = (struct rtentry4 *)rn;
	struct sockaddr_ip4 *dst = (struct sockaddr_ip4 *)rt_key(rt);
	struct sockaddr_ip4 *mask = (struct sockaddr_ip4 *)rt_mask(rt);
	struct direct_entry *fdesc = &_direct_tbl[chunk];
	struct range_entry_long *fp =
	    &_range_tbl[fdesc->base + fdesc->fragments];
	struct dxr_heap_entry *fhp = &_dxr_heap[_heap_index];
	uint32_t first = chunk << DXR_RANGE_SHIFT;
	uint32_t last = first | DXR_RANGE_MASK;
	uint32_t start, end;
	uint32_t preflen, nh;

	start = ntohl(dst->sac_addr);
	if (mask) {
		preflen = ffs(ntohl(mask->sac_addr));
		if (preflen)
			preflen = 33 - preflen;
		end = start | ~ntohl(mask->sac_addr);
	} else {
		preflen = 32;
		end = start;
	}
	if (start > last)
		return (-1);	/* Beyond chunk boundaries, we are done */
	if (start < first)
		return (0);	/* Skip this route */
	nh = rt->nh;

	if (start == fhp->start) {
		assert(preflen <= fhp->preflen);
		dxr_heap_inject(start, end, preflen, nh);
	} else if (start < fhp->start) {
		/* This MUST NEVER happen! */
		assert(start >= fhp->start);
	} else {
		/* start > fhp->start */
		while (start > fhp->end) {
			uint32_t oend = fhp->end;

			if (_heap_index > 0) {
				fhp--;
				_heap_index--;
			} else
				dxr_initheap(fhp->end + 1);
			if (fhp->end > oend && fhp->nexthop != fp->nexthop) {
				fp++;
				assert(fdesc->fragments < FRAG_MAX - 1);
				fdesc->fragments++;
				fp->start = (oend + 1) & DXR_RANGE_MASK;
				fp->nexthop = fhp->nexthop;
			}
		}
		if (start > ((chunk << DXR_RANGE_SHIFT) | fp->start) &&
		    nh != fp->nexthop) {
			fp++;
			assert(fdesc->fragments < FRAG_MAX - 1);
			fdesc->fragments++;
			fp->start = start & DXR_RANGE_MASK;
		} else if (fdesc->fragments) {
			if ((--fp)->nexthop == nh)
				fdesc->fragments--;
			else
				fp++;
		}
		fp->nexthop = nh;
		dxr_heap_inject(start, end, preflen, nh);
	}

	return (0);
}

void
DXRIPLookup::update_chunk(uint32_t chunk)
{
	struct sockaddr_ip4 dst, mask;
	struct direct_entry *fdesc = &_direct_tbl[chunk];
	struct range_entry_short *fp;
	struct dxr_heap_entry *fhp;
	uint32_t first = chunk << DXR_RANGE_SHIFT;
	uint32_t last = first | DXR_RANGE_MASK;
	struct dxr_walk_arg dwa;

	if (fdesc->fragments != FRAG_MAX)
		chunk_unref(chunk);

#if (DXR_DIRECT_BITS < 16)
	update_chunk_long(chunk);
	return;
#endif

	fdesc->base = _range_tbl_free;
	fdesc->fragments = 0;
	fdesc->long_format = 0;

	dxr_initheap(first);
	if (_dxr_heap[0].nexthop > 0xff) {
		update_chunk_long(chunk);
		return;
	}

	fp = (struct range_entry_short *) &_range_tbl[_range_tbl_free];
	fp->start = (first & DXR_RANGE_MASK) >> 8;
	fp->nexthop = _dxr_heap[0].nexthop;

	memset(&dst, 0, sizeof(dst));
	memset(&mask, 0, sizeof(mask));
	dst.sac_len = mask.sac_len = sizeof(sockaddr_ip4);
	dst.sac_addr = htonl(first);
	mask.sac_addr = htonl(~DXR_RANGE_MASK);
	dwa.obj = this;
	dwa.chunk = chunk;

	if (_ip_rnh->rnh_walktree_from(_ip_rnh, &dst, &mask,
	    dxr_walk_trampoline, (void *) &dwa) == ERANGE) {
		update_chunk_long(chunk);
		return;
	}

	/* Flush any remaining objects on the dxr_heap */
	fp = (struct range_entry_short *) &_range_tbl[_range_tbl_free] +
	    fdesc->fragments;
	fhp = &_dxr_heap[_heap_index];
	while (fhp->preflen > DXR_DIRECT_BITS) {
		uint32_t oend = fhp->end;

		if (_heap_index > 0) {
			fhp--;
			_heap_index--;
		} else
			dxr_initheap(fhp->end + 1);
		if (fhp->end > oend && fhp->nexthop != fp->nexthop) {
			/* Have we crossed the upper chunk boundary? */
			if (oend >= last)
				break;
			if (fhp->nexthop > 0xff) {
				update_chunk_long(chunk);
				return;
			}
			fp++;
			fdesc->fragments++;
			fp->start = ((oend + 1) & DXR_RANGE_MASK) >> 8;
			fp->nexthop = fhp->nexthop;
		}
	}

	/*
	 * If the chunk contains only a single fragment, encode
	 * nexthop in the .base field of the direct lookup table.
	 * In such a case we do not need to store the original chunk
	 * itself any more.
	 *
	 * The actual number of fragments is fdesc->fragments + 1.
	 */
	if (fdesc->fragments) {
		if ((fdesc->fragments & 1) == 0) {
			/* Align mpool_free on a 32 bit boundary */
			fp[1].start = fp->start;
			fp[1].nexthop = fp->nexthop;
			assert(fdesc->fragments < FRAG_MAX - 1);
			fdesc->fragments++;
		};
		_chunks_short++;
		_fragments_short += (fdesc->fragments + 1);
		fdesc->fragments >>= 1;
		_range_tbl_free += (fdesc->fragments + 1);
		assert(_range_tbl_free <= BASE_MAX);
		chunk_ref(chunk);
	} else {
		fdesc->base = fp->nexthop;
		fdesc->fragments = FRAG_MAX;
	}

	_pending_bitmask[chunk >> 5] &= ~(1 << (chunk & 0x1f));
}


void
DXRIPLookup::update_chunk_long(uint32_t chunk)
{
	struct sockaddr_ip4 dst, mask;
	struct direct_entry *fdesc = &_direct_tbl[chunk];
	struct range_entry_long *fp;
	struct dxr_heap_entry *fhp;
	uint32_t first = chunk << DXR_RANGE_SHIFT;
	uint32_t last = first | DXR_RANGE_MASK;
	struct dxr_walk_arg dwa;

	fdesc->base = _range_tbl_free;
	fdesc->fragments = 0;
	fdesc->long_format = 1;

	dxr_initheap(first);
	fp = &_range_tbl[_range_tbl_free];
	fp->start = first & DXR_RANGE_MASK;
	fp->nexthop = _dxr_heap[0].nexthop;

	memset(&dst, 0, sizeof(dst));
	memset(&mask, 0, sizeof(mask));
	dst.sac_len = mask.sac_len = sizeof(sockaddr_ip4);
	dst.sac_addr = htonl(first);
	mask.sac_addr = htonl(~DXR_RANGE_MASK);
	dwa.obj = this;
	dwa.chunk = chunk;

	_ip_rnh->rnh_walktree_from(_ip_rnh, &dst, &mask,
	    dxr_walk_long_trampoline, (void *) &dwa);

	/* Flush any remaining objects on the dxr_heap */
	fp = &_range_tbl[fdesc->base + fdesc->fragments];
	fhp = &_dxr_heap[_heap_index];
	while (fhp->preflen > DXR_DIRECT_BITS) {
		uint32_t oend = fhp->end;

		if (_heap_index > 0) {
			fhp--;
			_heap_index--;
		} else
			dxr_initheap(fhp->end + 1);
		if (fhp->end > oend && fhp->nexthop != fp->nexthop) {
			/* Have we crossed the upper chunk boundary? */
			if (oend >= last)
				break;
			fp++;
			assert(fdesc->fragments < FRAG_MAX);
			fdesc->fragments++;
			fp->start = (oend + 1) & DXR_RANGE_MASK;
			fp->nexthop = fhp->nexthop;
		}
	}

	/*
	 * If the chunk contains only a single fragment, encode
	 * nexthop in the fragments field of the direct lookup table.
	 * In such a case we do not need to store the original chunk
	 * itself any more.
	 */
	if (fdesc->fragments) {
		_chunks_long++;
		_fragments_long += (fdesc->fragments + 1);
		_range_tbl_free += (fdesc->fragments + 1);
		assert(_range_tbl_free <= BASE_MAX);
		chunk_ref(chunk);
	} else {
		fdesc->base = fp->nexthop;
		fdesc->fragments = FRAG_MAX;
	}

	_pending_bitmask[chunk >> 5] &= ~(1 << (chunk & 0x1f));
}


void
DXRIPLookup::dxr_initheap(uint32_t dst)
{
	struct rtentry4 *rt;
	struct sockaddr_ip4 sac;
	struct dxr_heap_entry *fhp = &_dxr_heap[0];

	_heap_index = 0;

	sac.sac_len = sizeof(sac);
	sac.sac_addr = htonl(dst);

	struct radix_node *rn = _ip_rnh->rnh_matchaddr(&sac, _ip_rnh);
	if (rn && ((rn->rn_flags & RNF_ROOT) == 0))
		rt = (struct rtentry4 *) rn;
	else
		rt = NULL;

	if (rt != NULL) {
		struct sockaddr_ip4 *dst =
		    (struct sockaddr_ip4 *)rt_key(rt);
		struct sockaddr_ip4 *mask =
		    (struct sockaddr_ip4 *)rt_mask(rt);

		fhp->start = ntohl(dst->sac_addr);

		if (mask) {
			fhp->preflen = ffs(ntohl(mask->sac_addr));
			if (fhp->preflen)
				fhp->preflen = 33 - fhp->preflen;
			fhp->end = fhp->start | ~ntohl(mask->sac_addr);
		} else {
			fhp->preflen = 32;
			fhp->end = fhp->start;
		}
		fhp->nexthop = rt->nh;
	} else {
		fhp->start = 0;
		fhp->end = 0xffffffff;
		fhp->preflen = 0;
		fhp->nexthop = 0;
	}
}


void
DXRIPLookup::prune_empty_chunks(void)
{
	struct chunk_desc *cdp1, *cdp2;
	uint32_t from, to, len;
	int chunk;

	for (cdp1 = LIST_FIRST(&_unused_chunks); cdp1 != NULL;
	    cdp1 = LIST_FIRST(&_unused_chunks)) {
		from = cdp1->cd_base + cdp1->cd_max_size;
		to = cdp1->cd_base;
		cdp2 = LIST_NEXT(cdp1, cd_hash_le);
		if (cdp2 != NULL) {
	 		/* Case A: more than one chunk */
			len = cdp2->cd_base - from;
			cdp2->cd_max_size += cdp1->cd_max_size;
		} else {
			/* Single empty chunk found */
			cdp2 = LIST_FIRST(&_all_chunks);
			if (cdp1 != cdp2) {
	 			/* Case B: not the last chunk on the heap */
				len = _range_tbl_free - from;
				_range_tbl_free -= cdp1->cd_max_size;
			} else {
				/* Case C: is the last chunk on the heap */
				_range_tbl_free -= cdp1->cd_max_size;
				LIST_REMOVE(cdp1, cd_all_le);
				LIST_REMOVE(cdp1, cd_hash_le);
				free(cdp1);
				break;
			}
		}
		bcopy(&_range_tbl[from], &_range_tbl[to],
		    len * sizeof(*_range_tbl));
		do  {
			cdp2->cd_base -= cdp1->cd_max_size;
			for (chunk = cdp2->cd_chunk_first; chunk >= 0;
			    chunk = _cptbl[chunk].cp_chunk_next)
				if (_direct_tbl[chunk].fragments != FRAG_MAX)
					_direct_tbl[chunk].base -=
					    cdp1->cd_max_size;
			cdp2 = LIST_NEXT(cdp2, cd_all_le);
		} while (cdp2 != cdp1);
		LIST_REMOVE(cdp1, cd_all_le);
		LIST_REMOVE(cdp1, cd_hash_le);
		free(cdp1);
	}
}


uint32_t
DXRIPLookup::chunk_hash(struct direct_entry *fdesc)
{
	uint32_t *p = (uint32_t *) &_range_tbl[fdesc->base];
	uint32_t *l = (uint32_t *) &_range_tbl[fdesc->base + fdesc->fragments];
	uint32_t hash = fdesc->fragments;

	for (; p <= l; p++)
		hash = (hash << 1) + (hash >> 1) + *p;

	return (hash + (hash >> 16));
}


void
DXRIPLookup::chunk_ref(uint32_t chunk)
{
	struct direct_entry *fdesc = &_direct_tbl[chunk];
	struct chunk_desc *cdp, *empty_cdp;
	uint32_t hash = chunk_hash(fdesc);
	uint32_t base = fdesc->base;
	uint32_t size = fdesc->fragments + 1;

	/* Find an already existing chunk descriptor */
	LIST_FOREACH(cdp, &_chunk_hashtbl[hash & CHUNK_HASH_MASK],
	    cd_hash_le) {
		if (cdp->cd_hash == hash && cdp->cd_cur_size == size &&
		    memcmp(&_range_tbl[base], &_range_tbl[cdp->cd_base],
		    sizeof(struct range_entry_long) * size) == 0) {
			cdp->cd_refcount++;
			fdesc->base = cdp->cd_base;
			if (fdesc->long_format) {
				_aggr_chunks_long++;
				_aggr_fragments_long += size;
				_chunks_long--;
				_fragments_long -= size;
			} else {
				_aggr_chunks_short++;
				_aggr_fragments_short += (size << 1);
				_chunks_short--;
				_fragments_short -= (size << 1);
			}
			_range_tbl_free -= size;
			/* Link in the chunk */
			_cptbl[chunk].cp_cdp = cdp;
			_cptbl[chunk].cp_chunk_next = cdp->cd_chunk_first;
			cdp->cd_chunk_first = chunk;
			return;
		}
	}

	/* No matching chunks found. Recycle an empty or allocate a new one */
	cdp = NULL;
	LIST_FOREACH(empty_cdp, &_unused_chunks, cd_hash_le) {
		if (empty_cdp->cd_max_size >= size &&
		    (cdp == NULL ||
		    empty_cdp->cd_max_size < cdp->cd_max_size)) {
			cdp = empty_cdp;
			if (empty_cdp->cd_max_size == size)
				break;
		}
	}

	if (cdp != NULL) {
		/* Copy from heap into the recycled chunk */
		bcopy(&_range_tbl[fdesc->base], &_range_tbl[cdp->cd_base],
		    size * sizeof(struct range_entry_long));
		fdesc->base = cdp->cd_base;
		_range_tbl_free -= size;
		if (cdp->cd_max_size > size + 0) { /* XXX hardcoded const! */
			/* Alloc a new (empty) descriptor */
			empty_cdp =
			    (struct chunk_desc *) malloc(sizeof(*empty_cdp));
			assert(empty_cdp != NULL);
			empty_cdp->cd_max_size = cdp->cd_max_size - size;
			empty_cdp->cd_base = cdp->cd_base + size;
			empty_cdp->cd_chunk_first = -1;
			empty_cdp->cd_cur_size = 0;
			LIST_INSERT_BEFORE(cdp, empty_cdp, cd_all_le);
			LIST_INSERT_AFTER(cdp, empty_cdp, cd_hash_le);
			cdp->cd_max_size = size;
		}
		LIST_REMOVE(cdp, cd_hash_le);
	} else {
		/* Alloc a new descriptor */
		cdp = (struct chunk_desc *) malloc(sizeof(*cdp));
		assert(cdp != NULL);
		cdp->cd_max_size = size;
		cdp->cd_base = fdesc->base;
		LIST_INSERT_HEAD(&_all_chunks, cdp, cd_all_le);
	}

	cdp->cd_hash = hash;
	cdp->cd_refcount = 1;
	cdp->cd_cur_size = size;
	cdp->cd_chunk_first = chunk;
	_cptbl[chunk].cp_cdp = cdp;
	_cptbl[chunk].cp_chunk_next = -1;
	LIST_INSERT_HEAD(&_chunk_hashtbl[hash & CHUNK_HASH_MASK], cdp,
	    cd_hash_le);
}


void
DXRIPLookup::chunk_unref(uint32_t chunk)
{
	struct direct_entry *fdesc = &_direct_tbl[chunk];
	struct chunk_desc *cdp = _cptbl[chunk].cp_cdp;
	struct chunk_desc *unused_cdp;
	int size = fdesc->fragments + 1;
	int i;

	if (--cdp->cd_refcount > 0) {
		if (fdesc->long_format) {
			_aggr_fragments_long -= size;
			_aggr_chunks_long--;
		} else {
			_aggr_fragments_short -= (size << 1);
			_aggr_chunks_short--;
		}
		/* Unlink chunk */
		if (cdp->cd_chunk_first == (int) chunk)
			cdp->cd_chunk_first = _cptbl[chunk].cp_chunk_next;
		else {
			for (i = cdp->cd_chunk_first;
			    _cptbl[i].cp_chunk_next != (int) chunk;
			    i = _cptbl[i].cp_chunk_next) {};
			_cptbl[i].cp_chunk_next = _cptbl[chunk].cp_chunk_next;
		}
		return;
	}

	LIST_REMOVE(cdp, cd_hash_le);
	cdp->cd_chunk_first = -1;
	cdp->cd_cur_size = 0;

	/* Keep unused chunks sorted with ascending base indices */
	if (LIST_EMPTY(&_unused_chunks))
		LIST_INSERT_HEAD(&_unused_chunks, cdp, cd_hash_le);
	else LIST_FOREACH(unused_cdp, &_unused_chunks, cd_hash_le) {
		if (unused_cdp->cd_base > cdp->cd_base) {
			LIST_INSERT_BEFORE(unused_cdp, cdp, cd_hash_le);
			break;
		}
		if (LIST_NEXT(unused_cdp, cd_hash_le) == NULL) {
			LIST_INSERT_AFTER(unused_cdp, cdp, cd_hash_le);
			break;
		}
	}

	/* Merge adjacent empty chunks */
	if ((unused_cdp = LIST_NEXT(cdp, cd_all_le)) != NULL &&
	    cdp == LIST_NEXT(unused_cdp, cd_hash_le)) {
		LIST_REMOVE(cdp, cd_hash_le);
		LIST_REMOVE(cdp, cd_all_le);
		unused_cdp->cd_max_size += cdp->cd_max_size;
		free(cdp);
		cdp = unused_cdp;
	}
	if ((unused_cdp = LIST_NEXT(cdp, cd_hash_le)) != NULL &&
	    cdp == LIST_NEXT(unused_cdp, cd_all_le)) {
		LIST_REMOVE(unused_cdp, cd_hash_le);
		LIST_REMOVE(unused_cdp, cd_all_le);
		cdp->cd_max_size += unused_cdp->cd_max_size;
		free(unused_cdp);
	}

	if (fdesc->long_format) {
		_chunks_long--;
		_fragments_long -= size;
	} else {
		_chunks_short--;
		_fragments_short -= (size << 1);
	}
}


int
DXRIPLookup::add_route(const IPRoute &r, bool set, IPRoute* old_route, ErrorHandler *e)
{
	int nh;

	nh = this->BSDIPLookup::add_route(r, set, old_route, e);
	if (nh >= 0) {
		assert(nh <= FRAG_MAX);
		schedule_update(r);
		return (0);
	} else
		return (nh);
}


int
DXRIPLookup::remove_route(const IPRoute& r, IPRoute* old_route, ErrorHandler *e)
{
	int res;

	res = this->BSDIPLookup::remove_route(r, old_route, e);
	if (res >= 0)
		schedule_update(r);
	return (res);
}


/*
 * Binary search for a matching range - the magic happens here in
 * this simple loop (unrolling is just an optimization).
 */
#define	DXR_LOOKUP_STAGE				 	\
	if (masked_dst < range[middle].start) {		 	\
		upperbound = middle;			 	\
		middle = (middle + lowerbound) / 2;	 	\
	} else if (masked_dst < range[middle + 1].start) {	\
		lowerbound = middle;			 	\
		break;					 	\
	} else {					 	\
		lowerbound = middle + 1;		 	\
		middle = (upperbound + middle + 1) / 2;		\
	}							\
	if (upperbound == lowerbound)				\
		break;


int
DXRIPLookup::lookup_route(IPAddress a, IPAddress &gw) const
{
	int nh = lookup_nexthop(ntohl(a.addr()));

#if 0
	/* Consistency check */
	int i = BSDIPLookup::lookup_route(a, gw);
	if (i != NH2PORT(nh) || gw != NH2GW(nh)) {
		printf("%s: ", a.unparse().c_str());
		printf("BSD (%s %d) ", gw.unparse().c_str(), i);
		printf("DXR %d (%s %d)\n", nh, NH2GW(nh).unparse().c_str(),
		    NH2PORT(nh));
	}
#endif
	gw = NH2GW(nh);
	return (NH2PORT(nh));
}


int
DXRIPLookup::lookup_nexthop(uint32_t dst) const
{
	uint32_t *fdescp;
	int32_t nh;
	uint32_t masked_dst;
	uint32_t upperbound;
	uint32_t middle;
	uint32_t lowerbound;

	masked_dst = dst & DXR_RANGE_MASK;
	fdescp = (uint32_t *) &_direct_tbl[dst >> DXR_RANGE_SHIFT];

	lowerbound = *fdescp;
	nh = lowerbound >> (32 - DESC_BASE_BITS); /* nh == .base */
	if ((lowerbound & FRAG_MAX) != FRAG_MAX) { /* not a direct hit? */
		if (lowerbound & LONG_FORMAT_BIT) { /* .long_format set? */
			register struct range_entry_long *range;

			upperbound = lowerbound & FRAG_MAX; /* .fragments */
			range = &_range_tbl[nh]; /* nh == .base */
			middle = upperbound / 2;
			lowerbound = 0;

			do {
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
			} while (1);
			nh = range[lowerbound].nexthop;
		} else {
			register struct range_entry_short *range;

			middle = lowerbound & FRAG_MAX; /* .fragments */
			masked_dst >>= 8;
			range = (struct range_entry_short *) &_range_tbl[nh];
			upperbound = middle * 2 + 1;
			lowerbound = 0;

			do {
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
				DXR_LOOKUP_STAGE
			} while (1);
			nh = range[lowerbound].nexthop;
		}
	}
	return (nh);
}


void
DXRIPLookup::flush_table()
{

	BSDIPLookup::flush_table();
	assert(_nexthop_head == -1); /* No allocated nexthops */

	memset(_pending_bitmask, 0xff,
	    sizeof(uint32_t) * (DIRECT_TBL_SIZE >> 5));
	_pending_start = 0;
	_pending_end = DIRECT_TBL_SIZE - 1;
	_updates_pending = 1;
	apply_pending();
	assert(_chunks_short == 0);
	assert(_chunks_long == 0);
	assert(_fragments_short == 0);
	assert(_fragments_long == 0);
	assert(_range_tbl_free == 0);
}
 

int
DXRIPLookup::flush_handler(const String &, Element *e, void *, ErrorHandler *)
{
	DXRIPLookup *t = static_cast<DXRIPLookup *>(e);

	t->flush_table();
	return (0);
}


String
DXRIPLookup::status_handler(Element *e, void *)
{
	DXRIPLookup *t = static_cast<DXRIPLookup *>(e);
	StringAccum sa;
	struct chunk_desc *cdp;
	uint32_t max_chunk = 0;
	uint32_t direct_size = sizeof(struct direct_entry) * DIRECT_TBL_SIZE;
	uint32_t range_size = sizeof(range_entry_long) * t->_range_tbl_free;
	uint32_t ratio10;
	uint32_t chunk_sizes[32];
	uint32_t i, j, size;
 
	LIST_FOREACH(cdp, &t->_all_chunks, cd_all_le)
		if (cdp->cd_cur_size > max_chunk)
			max_chunk = cdp->cd_cur_size;
	for (i = 0; i < 32; i++)
		chunk_sizes[i] = 0;
	for (i = 0; i < DIRECT_TBL_SIZE; i++) {
		size = t->_direct_tbl[i].fragments;
		if (size == FRAG_MAX) {
			chunk_sizes[0]++;
			continue;
		}
		if (t->_direct_tbl[i].long_format == 0)
			size = size * 2 + 1;
		else
			size = size + 1;
		if (size > max_chunk)
			max_chunk = size;
		for (j = 1; (1 << j) < FRAG_MAX; j++)
			if (size < ((uint32_t) 1 << j)) {
				chunk_sizes[j]++;
				break;
			}
	}

	sa << t->class_name() << " (D" << DXR_DIRECT_BITS << "R): ";
	sa << t->_prefix_cnt << " prefixes, ";
	sa << t->_nexthops << " unique nexthops\n";

	sa << "Lookup tables: ";
	sa << direct_size << " bytes direct, ";
	sa << range_size << " bytes range";
	if (t->_prefix_cnt) {
		ratio10 = 10 * (direct_size + range_size) / t->_prefix_cnt;
		sa << " (" << ratio10 / 10 << "." <<
		    ratio10 % 10 << " bytes/prefix)\n";
	} else
		sa << "\n";

	for (i = 0; (1 << i) < FRAG_MAX; i++) {
		if (chunk_sizes[i] == 0)
			continue;
		sa << "Chunks with ";
		if (i < 2)
			sa << (1 << i);
		else
			sa << (1 << (i - 1)) + 1 << " - " << (1 << i);
		if (i == 0)
			sa << " fragment: " << chunk_sizes[i];
		else
			sa << " fragments: " << chunk_sizes[i];
		sa << " (" << 100 * chunk_sizes[i] / DIRECT_TBL_SIZE << ".";
		sa << (1000 * chunk_sizes[i] / DIRECT_TBL_SIZE) % 10 << "%)\n";
	}

	sa << "Longest range chunk contains " << max_chunk << " fragments\n";
	sa << "Physical chunks: " << t->_chunks_short << " short, ";
	sa << t->_chunks_long << " long\n";
	sa << "Physical fragments: " << t->_fragments_short << " short, ";
	sa << t->_fragments_long << " long\n";
	sa << "Aggregated chunks: ";
	sa << t->_aggr_chunks_short + t->_chunks_short << " short, ";
	sa << t->_aggr_chunks_long + t->_chunks_long << " long\n";
	sa << "Aggregated fragments: ";
	sa << t->_aggr_fragments_short + t->_fragments_short << " short, ";
	sa << t->_aggr_fragments_long + t->_fragments_long << " long\n";
	sa << "Last update duration: " << t->_last_update_us / 1000 << "." <<
	    (t->_last_update_us % 1000) / 100 << " ms\n";

	return (sa.take_string());
} 


int
DXRIPLookup::bench_select(const String &s, Element *e, void *,
    ErrorHandler *)
{
	DXRIPLookup *t = static_cast<DXRIPLookup *>(e);
	int type;

	if (t->_key_tbl != NULL)
		CLICK_LFREE(t->_key_tbl, sizeof(*t->_key_tbl) * t->_test_blk);
	if (t->_nh_tbl != NULL)
		CLICK_LFREE(t->_nh_tbl, sizeof(*t->_nh_tbl) * t->_test_blk);

	type = atoi(s.c_str());
	if (type < 0 || type > 5)
		return (-ERANGE);
	t->_bench_sel = type;
	return (0);
}


int
DXRIPLookup::thread_select(const String &s, Element *e, void *,
    ErrorHandler *)
{
	DXRIPLookup *t = static_cast<DXRIPLookup *>(e);
	int i, n, ncpus;
	cpuset_t cpuset;

	n = atoi(s.c_str());
	if (pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset)
	    != 0)
		err(EX_OSERR, "pthread_getaffinity_np() failed");
	for (ncpus = 0, i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &cpuset))
			ncpus++;

	if (n < 1 || n > ncpus)
		return (-ERANGE);
	t->_bench_threads = n;
	return (0);
}


struct bench_info {
	DXRIPLookup *t;
	pthread_t td;
	int id;
	int done;
	uint32_t *key_tbl;
	uint16_t *nh_tbl;
	Timestamp t_start, t_len;
	char pad[128]; /* XXX padding to fill cache line? */
};


static void *
bench_trampoline(void *arg)
{
	struct bench_info *bi = (struct bench_info *) arg;

	bi->t->bench_thread(bi);

	return (NULL); // Appease compiler warnings
}


#define TEST_BLK (256 * 1024 * 1024)

void
DXRIPLookup::bench_thread(void *arg)
{
	struct bench_info *bi = (struct bench_info *) arg;
	Timestamp t_start;
	uint32_t off;

	off = ((bi->t->_test_blk / bi->t->_bench_threads) & ~0xf) * bi->id;
	/* Do the benchmark */
	t_start = Timestamp::now();
	switch (_bench_sel % 3) {
	case 0:
		bench_seq(bi->key_tbl, bi->nh_tbl, off);
		break;
	case 1:
		bench_rnd(bi->key_tbl, bi->nh_tbl, off);
		break;
	case 2:
		bench_rep(bi->key_tbl, bi->nh_tbl, off);
		break;
	};
	bi->t_len = Timestamp::now() - t_start;
	bi->done = 1;
}


int
DXRIPLookup::prepare_handler(const String &s, Element *e, void *,
    ErrorHandler *)
{
	DXRIPLookup *t = static_cast<DXRIPLookup *>(e);
	int n, key;
	size_t i;

	if (t->_key_tbl != NULL)
		CLICK_LFREE(t->_key_tbl, sizeof(*t->_key_tbl) * t->_test_blk);
	if (t->_nh_tbl != NULL)
		CLICK_LFREE(t->_nh_tbl, sizeof(*t->_nh_tbl) * t->_test_blk);

	n = atoi(s.c_str());
	t->_test_blk = n * 1024 * 1024;

	t->_key_tbl =
	    (uint32_t *) CLICK_LALLOC(sizeof(*t->_key_tbl) * t->_test_blk);
	t->_nh_tbl =
	    (uint16_t *) CLICK_LALLOC(sizeof(*t->_nh_tbl) * t->_test_blk);
	assert(t->_key_tbl != NULL);
	assert(t->_nh_tbl != NULL);

	/* Populate input vector with random keys */
	for (i = 0; i < t->_test_blk; i++) {
		/* Exclude unannounced address space for tests 3, 4 and 5 */
		do {
			key = random();
		} while (t->_bench_sel > 3 && t->lookup_nexthop(key) == 0);
		t->_key_tbl[i] = key;
		/* map the memory for the results now, not during the test */
		t->_nh_tbl[i] = key;
	}

	return (0);
}

String
DXRIPLookup::bench_handler(Element *e, void *)
{
	DXRIPLookup *t = static_cast<DXRIPLookup *>(e);
	StringAccum sa;
	int i, time_ms;
	uint64_t klps, len = t->_test_blk;
	struct bench_info bi[16];
	cpuset_t cpuset;
	Timestamp t_len;

	if (t->_key_tbl == NULL || t->_nh_tbl == NULL) {
		sa << "ERROR: key stream uninitialized\n";
		return (sa.take_string());
	}

	for (i = 0; i < t->_bench_threads; i++) {
		bi[i].t = t;
		bi[i].id = i;
		bi[i].key_tbl = t->_key_tbl;
		bi[i].nh_tbl = t->_nh_tbl;
		bi[i].done = 0;
		if (pthread_create(&bi[i].td, NULL, bench_trampoline,
		    (void *) &bi[i]) == -1)
			err(EX_OSERR, "Can't start RX threads");
		CPU_ZERO(&cpuset);
		CPU_SET(i, &cpuset);
		if (pthread_setaffinity_np(bi[i].td, sizeof(cpuset),
		    &cpuset) != 0)
			err(EX_OSERR, "pthread_setaffinity_np() failed");
	}

	do {
		sleep(1);
		for (i = 0; i < t->_bench_threads; i++)
			if (bi[i].done == 0)
				break;
	} while (i < t->_bench_threads);

	t_len = bi[0].t_len;
	for (i = 1; i < t->_bench_threads; i++)
		t_len = t_len + bi[i].t_len;
	t_len = t_len / t->_bench_threads;
	time_ms = t_len.sec() * 1000 + t_len.usec() / 1000;
	klps = len * t->_bench_threads / time_ms;

	sa << t->class_name() << " (D" << DXR_DIRECT_BITS << "R), ";
	switch (t->_bench_sel % 3) {
	case 0:
		sa << "SEQ test, ";
		break;
	case 1:
		sa << "RND test, ";
		break;
	case 2:
		sa << "REP test, ";
		break;
	};
	if (t->_bench_sel > 2)
		sa << "random keys from announced address space:\n";
	else
		sa << "uniformly random keys:\n";
	sa << len * t->_bench_threads << " lookups in " << t_len << " s (";
	sa << klps / 1000 << "." << (klps % 1000) / 100 << " MLps)\n";

	return (sa.take_string());
}


void
DXRIPLookup::bench_seq(uint32_t *key_tbl, uint16_t *nh_tbl, uint32_t offset)
{
	int nh = 0;
	int size = _test_blk;
	uint32_t *key_ptr;
	uint16_t *nh_ptr;

#define SEQ_STAGE							\
	do {								\
		nh = lookup_nexthop(*key_ptr++ + (nh >> 15));		\
		*nh_ptr++ = nh;						\
	} while (0)

	while (size > 0) {
		key_ptr = &key_tbl[offset];
		nh_ptr = &nh_tbl[offset];
		offset += 8;
		if (offset >= _test_blk)
			offset = 0;
		/* Manual unrolling for better throughput */
		SEQ_STAGE; SEQ_STAGE; SEQ_STAGE; SEQ_STAGE;
		SEQ_STAGE; SEQ_STAGE; SEQ_STAGE; SEQ_STAGE;
		size -= 8;
	}
}


void
DXRIPLookup::bench_rnd(uint32_t *key_tbl, uint16_t *nh_tbl, uint32_t offset)
{
	int size = _test_blk;
	uint32_t *key_ptr;
	uint16_t *nh_ptr;

#define RND_STAGE do {*nh_ptr++ = lookup_nexthop(*key_ptr++);} while (0)

	while (size > 0) {
		key_ptr = &key_tbl[offset];
		nh_ptr = &nh_tbl[offset];
		offset += 8;
		if (offset >= _test_blk)
			offset = 0;
		/* Manual unrolling for better throughput */
		RND_STAGE; RND_STAGE; RND_STAGE; RND_STAGE;
		RND_STAGE; RND_STAGE; RND_STAGE; RND_STAGE;
		size -= 8;
	}
}


void
DXRIPLookup::bench_rep(uint32_t *key_tbl, uint16_t *nh_tbl, uint32_t offset)
{
	int size = _test_blk;
	uint32_t *key_ptr;
	uint16_t *nh_ptr;

	while (size > 0) {
		key_ptr = &key_tbl[offset];
		nh_ptr = &nh_tbl[offset];
		offset += 1; /* Reuse same key 8 times */
		if (offset >= _test_blk - 8)
			offset = 0;
		/* Manual unrolling for better throughput */
		RND_STAGE; RND_STAGE; RND_STAGE; RND_STAGE;
		RND_STAGE; RND_STAGE; RND_STAGE; RND_STAGE;
		size -= 8;
	}
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(BSDIPLookup)
EXPORT_ELEMENT(DXRIPLookup)
