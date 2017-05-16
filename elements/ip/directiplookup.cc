/*
 * directiplookup.{cc,hh} -- lookup for output port and next-hop gateway
 * in one to max. two DRAM accesses with potential CPU cache / TLB misses
 * Marko Zec
 *
 * Copyright (c) 2005, 2014 University of Zagreb
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
#include "directiplookup.hh"

#include <err.h>
#if defined(__FreeBSD__)
#include <pthread_np.h>
#include <pmc.h>
#else
#include <pthread.h>
#endif
#include <sysexits.h>
#include <unistd.h>

CLICK_DECLS

#define	PMC_COUNTERS 1

static const char *pmc_names_intel[] = {
	"llc-misses",
};

static const char *pmc_names_amd[] = {
	"dc-refill-from-system",
};

static const char **pmc_names;


DirectIPLookup::DirectIPLookup()
	: _secondary_used(0), _secondary_free_head(0),
	_updates_pending(0), _pending_start(DIR_CHUNKS),
	_pending_end(0), _update_scanner(this),
	_bench_sel(0), _bench_threads(1), _skip_smt(0),
	_key_tbl(NULL), _nh_tbl(NULL)
{
	int i, ncpus;
	pmc_id_t pmcid;
#if defined(__FreeBSD__)
	cpuset_t cpuset;
#else
	cpu_set_t cpuset;
#endif

	_primary = (uint16_t *)
	    CLICK_LALLOC(sizeof(*_primary) * PRIMARY_SIZE);
	_secondary = (uint16_t *)
	    CLICK_LALLOC(sizeof(*_secondary) * SECONDARY_SIZE);
	_pending_bitmask = (uint32_t *)
	    CLICK_LALLOC(sizeof(uint32_t) * (DIR_CHUNKS >> 5));
	_range_buf = (struct dir_range_entry *)
	    CLICK_LALLOC(sizeof(struct dir_range_entry) * 65536); /* XXX */
	assert(_primary != NULL);
	assert(_secondary != NULL);
	memset(_primary, 0xff, sizeof(*_primary) * PRIMARY_SIZE);
	/* Link all secondary blocks in a free list */
	for (i = 0; i < (1 << 15); i ++)
		_secondary[i << SECONDARY_BITS] = i + 1;

	if (pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset)
	    != 0)
		err(EX_OSERR, "pthread_getaffinity_np() failed");
	for (ncpus = 0, i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &cpuset))
			ncpus++;
	_ncpus = ncpus;

	if (pmc_init() != 0)
		err(EX_OSERR, "hwpmc(4) not loaded");

	if (pmc_allocate(pmc_names_amd[0], PMC_MODE_SC, 0, 0, &pmcid) == 0)
		pmc_names = pmc_names_amd;
	else if (pmc_allocate(pmc_names_intel[0], PMC_MODE_SC, 0, 0, &pmcid)
	    == 0)
		pmc_names = pmc_names_intel;
	else
		err(EX_OSERR, "failed to allocate pmcs");
}


DirectIPLookup::~DirectIPLookup()
{

	flush_table();
	CLICK_LFREE(_primary, sizeof(*_primary) * PRIMARY_SIZE);
	CLICK_LFREE(_secondary, sizeof(*_secondary) * SECONDARY_SIZE);
	CLICK_LFREE(_pending_bitmask, sizeof(uint32_t) * (DIR_CHUNKS >> 5));
	CLICK_LFREE(_range_buf, sizeof(struct dir_range_entry) * 65536);
}


void
DirectIPLookup::add_handlers()
{
	IPRouteTable::add_handlers();
	add_write_handler("flush", flush_handler, 0, Handler::BUTTON);
	add_read_handler("stat", status_handler, 0, Handler::BUTTON);
	add_read_handler("bench", bench_handler, 0, Handler::BUTTON);
	add_write_handler("bench_sel", bench_select, 0, Handler::BUTTON);
	add_write_handler("prepare", prepare_handler, 0, Handler::BUTTON);
	add_write_handler("threads", thread_select, 0, Handler::BUTTON);
	add_write_handler("skip_smt", skip_smt, 0, Handler::BUTTON);
}


int
DirectIPLookup::initialize(ErrorHandler *)
{
	_update_scanner.initialize(this);
	if (_pending_start <= _pending_end)
		apply_pending();
	return(0);
}


void
DirectIPLookup::schedule_update(const IPRoute &r)
{
	uint32_t start, end, chunk;

	/* Default route change requires no updates to lookup structures */
	if (r.prefix_len() == 0)
		return;

	start = ntohl(r.addr.addr());
	end = start | ~ntohl(r.mask.addr());

	start = start >> DIR_CHUNK_SHIFT;
	end = end >> DIR_CHUNK_SHIFT;
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
DirectIPLookup::run_timer(Timer *)
{
	if (_updates_pending)
		apply_pending();
}
 
 
void
DirectIPLookup::apply_pending(void)
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
	t_len = Timestamp::now() - t_start;
	_last_update_us = t_len.sec() * 1000000 + t_len.usec();

	_pending_start = DIR_CHUNKS;
	_pending_end = 0;
	_updates_pending = 0;
}


struct dir_walk_arg {
	DirectIPLookup *obj;
	uint32_t chunk;
};


static int
dir_walk_trampoline(struct radix_node *rn, void *arg)
{
	struct dir_walk_arg *dwa = (struct dir_walk_arg *) arg;

	return (dwa->obj->dir_walk(rn, dwa->chunk));
}


void
DirectIPLookup::dir_heap_inject(uint32_t start, uint32_t end, int preflen,
    int nh)
{
	struct dir_heap_entry *fhp;
	int i;

	for (i = _heap_index; i >= 0; i--) {
		if (preflen > _dir_heap[i].preflen)
			break;
		else if (preflen < _dir_heap[i].preflen) {
			bcopy(&_dir_heap[i], &_dir_heap[i+1],
			    sizeof(struct dir_heap_entry));
		} else {
			/* Already the only item on heap, do nothing */
			assert(_heap_index == 0 &&
			    preflen == _dir_heap[0].preflen &&
			    start == _dir_heap[0].start &&
			    end == _dir_heap[0].end &&
			    nh == _dir_heap[0].nexthop);
			return;
		}
	}

	fhp = &_dir_heap[i + 1];
	fhp->preflen = preflen;
	fhp->start = start;
	fhp->end = end;
	fhp->nexthop = nh;
	_heap_index++;
}


int
DirectIPLookup::dir_walk(struct radix_node *rn, uint32_t chunk)
{
	struct rtentry4 *rt = (struct rtentry4 *)rn;
	struct sockaddr_ip4 *dst = (struct sockaddr_ip4 *)rt_key(rt);
	struct sockaddr_ip4 *mask = (struct sockaddr_ip4 *)rt_mask(rt);
	struct dir_range_entry *fp = &_range_buf[_range_fragments];
	struct dir_heap_entry *fhp = &_dir_heap[_heap_index];
	uint32_t first = chunk << DIR_CHUNK_SHIFT;
	uint32_t last = first | DIR_CHUNK_MASK;
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
		dir_heap_inject(start, end, preflen, nh);
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
				dir_initheap(fhp->end + 1);
			if (fhp->end > oend && fhp->nexthop != fp->nexthop) {
				fp++;
				_range_fragments++;
				fp->start = oend + 1;
				fp->nexthop = fhp->nexthop;
			}
		}
		if (start > fp->start && nh != fp->nexthop) {
			fp++;
			_range_fragments++;
			fp->start = start;
		} else if (_range_fragments) {
			if ((--fp)->nexthop == nh)
				_range_fragments--;
			else
				fp++;
		}
		fp->nexthop = nh;
		dir_heap_inject(start, end, preflen, nh);
	}

	return (0);
}


void
DirectIPLookup::update_chunk(uint32_t chunk)
{
	struct sockaddr_ip4 dst, mask;
	struct dir_range_entry *fp = _range_buf;
	struct dir_heap_entry *fhp;
	uint32_t first = chunk << DIR_CHUNK_SHIFT;
	uint32_t last = first | DIR_CHUNK_MASK;
	uint32_t nh, i;
	struct dir_walk_arg dwa;

	_range_fragments = 0;
	dir_initheap(first);
	fp->start = first;
	fp->nexthop = _dir_heap[0].nexthop;

	memset(&dst, 0, sizeof(dst));
	memset(&mask, 0, sizeof(mask));
	dst.sac_len = mask.sac_len = sizeof(sockaddr_ip4);
	dst.sac_addr = htonl(first);
	mask.sac_addr = htonl(~DIR_CHUNK_MASK);
	dwa.obj = this;
	dwa.chunk = chunk;

	_ip_rnh->rnh_walktree_from(_ip_rnh, &dst, &mask,
	    dir_walk_trampoline, (void *) &dwa);

	/* Flush any remaining objects on the dir_heap */
	fp = &_range_buf[_range_fragments];
	fhp = &_dir_heap[_heap_index];
	while (fhp->preflen > DIR_CHUNK_PREFLEN) {
		uint32_t oend = fhp->end;

		if (_heap_index > 0) {
			fhp--;
			_heap_index--;
		} else
			dir_initheap(fhp->end + 1);
		if (fhp->end > oend && fhp->nexthop != fp->nexthop) {
			/* Have we crossed the upper chunk boundary? */
			if (oend >= last)
				break;
			fp++;
			_range_fragments++;
			fp->start = oend + 1;
			fp->nexthop = fhp->nexthop;
		}
	}

	/* Release references to secondary table held by old direct entries */
	for (i = chunk << (DIR_CHUNK_SHIFT - SECONDARY_BITS);
	    i < (chunk + 1) << (DIR_CHUNK_SHIFT - SECONDARY_BITS); i++) {
		nh = _primary[i];
		if ((nh & 0x8000) == 0) {
			_secondary[i << SECONDARY_BITS] = _secondary_free_head;
			_secondary_free_head = nh;
			_secondary_used--;
		}
	}

	/* Transform range notation to lookup table entries */
	first = _range_buf[0].start;
	nh = _range_buf[0].nexthop;
	for (i = 1; i <= _range_fragments; i++) {
		last = _range_buf[i].start;
		while (first < last) {
			if ((first & SECONDARY_MASK) == 0 &&
			    ((last & SECONDARY_MASK) == 0 ||
			    (first ^ last) >> SECONDARY_BITS != 0)) {
				/* Direct hit */
				_primary[first >> SECONDARY_BITS] = nh ^ 0xffff;
				first += (1 << SECONDARY_BITS);
			} else if ((first & SECONDARY_MASK) == 0) {
				/* Alloc a new secondary block */
				assert(_secondary_used < 32768);
				_primary[first >> SECONDARY_BITS] =
				    _secondary_free_head;
				_secondary_free_head = _secondary[
				    _secondary_free_head << SECONDARY_BITS];
				_secondary_used++;
				_secondary[_primary[first >> SECONDARY_BITS]
				    << SECONDARY_BITS] = nh;
				first++;
			} else {
				/* Fill up the secondary block */
				_secondary[(_primary[first >> SECONDARY_BITS]
				    << SECONDARY_BITS)
				    + (first & SECONDARY_MASK)] = nh;
				first++;
			}
		}
		nh = _range_buf[i].nexthop;
	};
	last = (chunk << DIR_CHUNK_SHIFT) + DIR_CHUNK_MASK;
	while (first < last) {
		if ((first & SECONDARY_MASK) == 0) {
			/* Direct hit */
			_primary[first >> SECONDARY_BITS] = nh ^ 0xffff;
			first += (1 << SECONDARY_BITS);
		} else {
			/* Fill up the secondary block */
			_secondary[(_primary[first >> SECONDARY_BITS]
			    << SECONDARY_BITS)
			    + (first & SECONDARY_MASK)] = nh;
			first++;
		}
		if (first == 0)
			break;	/* End of IPv4 range - overflow */
	}

	_pending_bitmask[chunk >> 5] &= ~(1 << (chunk & 0x1f));
}



void
DirectIPLookup::dir_initheap(uint32_t dst)
{
	struct rtentry4 *rt;
	struct sockaddr_ip4 sac;
	struct dir_heap_entry *fhp = &_dir_heap[0];

	_heap_index = 0;
	sac.sac_len = sizeof(sac);
	sac.sac_addr = htonl(dst);

	struct radix_node *rn = _ip_rnh->rnh_matchaddr(&sac, _ip_rnh);
	if (rn && ((rn->rn_flags & RNF_ROOT) == 0))
		rt = (struct rtentry4 *) rn;
	else
		rt = NULL;
 
	if (rt != NULL) {
		struct sockaddr_ip4 *dst = (struct sockaddr_ip4 *)rt_key(rt);
		struct sockaddr_ip4 *mask = (struct sockaddr_ip4 *)rt_mask(rt);
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


int
DirectIPLookup::add_route(const IPRoute &r, bool set, IPRoute* old_route,
    ErrorHandler *e)
{
	int res;

	res = this->BSDIPLookup::add_route(r, set, old_route, e);
	if (res >= 0)
		schedule_update(r);
	return(res);
}


int
DirectIPLookup::remove_route(const IPRoute& r, IPRoute* old_route,
    ErrorHandler *e)
{
	int res;

	res = this->BSDIPLookup::remove_route(r, old_route, e);
	if (res >= 0)
		schedule_update(r);
	return(res);
}


int
DirectIPLookup::lookup_route(IPAddress a, IPAddress &gw) const
{
	int nh = lookup_nexthop(ntohl(a.addr()));

#if 0
	/* Consistency check */
	int i = BSDIPLookup::lookup_route(a, gw);
	if (i != NH2PORT(nh) || gw != NH2GW(nh)) {
		printf("%s: ", a.unparse().c_str());
		printf("BSD (%s %d) ", gw.unparse().c_str(), i);
		printf("DIR %d (%s %d)\n", nh, NH2GW(nh).unparse().c_str(),
		    NH2PORT(nh));
	}
#endif
	gw = NH2GW(nh);
	return (NH2PORT(nh));
}


int
DirectIPLookup::lookup_nexthop(uint32_t dst) const
{
	uint16_t pri = _primary[dst >> SECONDARY_BITS];

	if (pri & 0x1000)
		return (pri ^ 0xffff);
	return (_secondary[(pri << SECONDARY_BITS) + (dst & SECONDARY_MASK)]);
}


void
DirectIPLookup::flush_table()
{

	BSDIPLookup::flush_table();
	assert(_nexthop_head == -1); /* No allocated nexthops */
	memset(_primary, 0xff, sizeof(*_primary) * PRIMARY_SIZE);
	_pending_start = DIR_CHUNKS;
	_pending_end = 0;
	_updates_pending = 0;
	_secondary_free_head = 0;
	_secondary_used = 0;
}

  
int
DirectIPLookup::flush_handler(const String &, Element *e, void *,
    ErrorHandler *)
{
	DirectIPLookup *t = static_cast<DirectIPLookup *>(e);

	t->flush_table();
	return (0);
}


String
DirectIPLookup::status_handler(Element *e, void *)
{
	DirectIPLookup *t = static_cast<DirectIPLookup *>(e);
	StringAccum sa;
	uint32_t direct_size = sizeof(uint16_t) * PRIMARY_SIZE;
	uint32_t secondary_size = (sizeof(uint16_t) << SECONDARY_BITS) *
	    t->_secondary_used;
	uint32_t ratio10;
	uint32_t direct_hits = 0;
	int i;

	for (i = 0; i < PRIMARY_SIZE; i++)
		if (t->_primary[i] & 0x8000)
			direct_hits++;
	sa << t->class_name() << " (DIR-" << DIRECT_BITS << "-" <<
	    SECONDARY_BITS << "): ";
	sa << t->_prefix_cnt << " prefixes, ";
	sa << t->_nexthops << " unique nexthops\n";

	sa << "Lookup tables: ";
	sa << direct_size << " bytes direct, ";
	sa << secondary_size << " bytes secondary";
	if (t->_prefix_cnt) {
		ratio10 = 10 * (direct_size + secondary_size) / t->_prefix_cnt;
		sa << " (" << ratio10 / 10 << "." <<
		    ratio10 % 10 << " bytes/prefix)\n";
	} else
		sa << "\n";

	ratio10 = 1000 * t->_secondary_used / 32768;
	sa << "Secondary table utilization: ";
	sa << ratio10 / 10 << "." << ratio10 % 10 << "%";
	sa << " (" << t->_secondary_used << " / 32768)\n";

	sa << "Direct table resolves " <<
	    direct_hits / (PRIMARY_SIZE / 100) << "." <<
	    (direct_hits / (PRIMARY_SIZE / 1000)) % 10 <<
	    "% of IPv4 address space\n";

	sa << "Last update duration: " << t->_last_update_us / 1000 << "." <<
	    (t->_last_update_us % 1000) / 100 << " ms\n";

	return (sa.take_string());
}


int
DirectIPLookup::bench_select(const String &s, Element *e, void *,
    ErrorHandler *)
{
	DirectIPLookup *t = static_cast<DirectIPLookup *>(e);
	int type;
	
	if (t->_key_tbl != NULL)
		CLICK_LFREE(t->_key_tbl, sizeof(*t->_key_tbl) * t->_test_blk);
	if (t->_nh_tbl != NULL)
		CLICK_LFREE(t->_nh_tbl, sizeof(*t->_nh_tbl) * t->_test_blk);
	t->_key_tbl = NULL;
	t->_nh_tbl = NULL;
	t->_test_blk = 0;

	type = atoi(s.c_str());
	if (type < 0 || type > 5)
		return (-ERANGE);
	t->_bench_sel = type;
	return (0);
}


int
DirectIPLookup::skip_smt(const String &s, Element *e, void *,
    ErrorHandler *)
{
	DirectIPLookup *t = static_cast<DirectIPLookup *>(e);
	int type;

	type = atoi(s.c_str());
	if (type < 0 || type > 1)
		return (-ERANGE);
	t->_skip_smt = type;
	return (0);
}


int
DirectIPLookup::thread_select(const String &s, Element *e, void *,
    ErrorHandler *)
{
	DirectIPLookup *t = static_cast<DirectIPLookup *>(e);
	int n;
	
	n = atoi(s.c_str());
	if (n < 1 || n > t->_ncpus)
		return (-ERANGE);
	t->_bench_threads = n;
	return (0);
}


struct bench_info {
	DirectIPLookup *t;
	pthread_t td;
	int index;
	int cpu;
	volatile int done;
	uint32_t *key_tbl;
	uint16_t *nh_tbl;
	Timestamp t_start, t_len;
	uint64_t lookups;
	uint64_t pmc[16];
	char pad[128]; /* XXX padding to fill cache line? */
};


static void *
bench_trampoline(void *arg)
{
	struct bench_info *bi = (struct bench_info *) arg;

	bi->t->bench_thread(bi);

	return (NULL); // appease compiler warnings
}


void
DirectIPLookup::bench_thread(void *arg)
{
	struct bench_info *bi = (struct bench_info *) arg;
	Timestamp t_start;
	uint32_t off;
	int i;
	pmc_id_t pmcid[PMC_COUNTERS];

	for (i = 0; i < PMC_COUNTERS; i++) {
		if (pmc_allocate(pmc_names[i], PMC_MODE_SC,
		    0, bi->cpu, &pmcid[i]) < 0)
			err(EX_OSERR, "failed to allocate pmc %s",
			    pmc_names[i]);
		if (pmc_write(pmcid[i], 0) < 0)
			err(EX_OSERR, "failed to zero counter %s",
			    pmc_names[i]);
		if (pmc_start(pmcid[i]) < 0)
			err(EX_OSERR, "failed to start counter %s",
			    pmc_names[i]);
	}

	off = ((bi->t->_test_blk / bi->t->_bench_threads) & ~0xf) * bi->index;

	/* Wait for the start marker */
	do {} while (_bench_active == 0);

	/* Do the benchmark */
	t_start = Timestamp::now();
	switch (_bench_sel % 3) {
	case 0:
		bi->lookups = bench_seq(bi->key_tbl, bi->nh_tbl, off);
		break;
	case 1:
		bi->lookups = bench_rnd(bi->key_tbl, bi->nh_tbl, off);
		break;
	case 2:
		bi->lookups = bench_rep(bi->key_tbl, bi->nh_tbl, off);
		break;
	};
	bi->t_len = Timestamp::now() - t_start;

	for (i = 0; i < PMC_COUNTERS; i++) {
		if (pmc_read(pmcid[i], &bi->pmc[i]) < 0)
			err(EX_OSERR, "failed to read counter %s",
			    pmc_names[i]);
		if (pmc_release(pmcid[i]) < 0)
			err(EX_OSERR, "failed to release %s", pmc_names[i]);
	}

	bi->done = 1;
}


int
DirectIPLookup::prepare_handler(const String &s, Element *e, void *,
    ErrorHandler *)
{
	DirectIPLookup *t = static_cast<DirectIPLookup *>(e);
	uint32_t n, key;
	size_t i;

	if (t->_key_tbl != NULL)
		CLICK_LFREE(t->_key_tbl, sizeof(*t->_key_tbl) * t->_test_blk);
	if (t->_nh_tbl != NULL)
		CLICK_LFREE(t->_nh_tbl, sizeof(*t->_nh_tbl) * t->_test_blk);
	t->_key_tbl = NULL;
	t->_nh_tbl = NULL;
	t->_test_blk = 0;

	n = atoi(s.c_str());
	if (n < 1 || n > 1024)
		return (ERANGE);

	t->_test_blk = n * 1024 * 1024;

	t->_key_tbl =
	    (uint32_t *) CLICK_LALLOC(sizeof(*t->_key_tbl) * t->_test_blk);
	t->_nh_tbl =
	    (uint16_t *) CLICK_LALLOC(sizeof(*t->_nh_tbl) * t->_test_blk);
	assert(t->_key_tbl != NULL);
	assert(t->_nh_tbl != NULL);

	/* Populate input vector with random keys */
	srandomdev();
	for (i = 0; i < t->_test_blk; i++) {
		/* Exclude unannounced address space for tests 3, 4 and 5 */
		do {
			key = random() << 1;
		} while (key >> 24 == 0 || key >> 24 == 127 || key >> 24 >= 224
		    || (t->_bench_sel > 3 && t->lookup_nexthop(key) == 0));
		t->_key_tbl[i] = key;
		/* map the memory for the results now, not during the test */
		t->_nh_tbl[i] = key;
	}

	return (0);
}

String
DirectIPLookup::bench_handler(Element *e, void *)
{
	DirectIPLookup *t = static_cast<DirectIPLookup *>(e);
	StringAccum sa;
	int i, time_ms, cpu;
	struct bench_info bi[256]; // XXX
	Timestamp t_len;
	uint64_t klps, lookups, pmc;
#if defined(__FreeBSD__)
	cpuset_t cpuset;
#else
	cpu_set_t cpuset;
#endif

	if (t->_key_tbl == NULL || t->_nh_tbl == NULL) {
		sa << "ERROR: key stream uninitialized\n";
		return (sa.take_string());
	}

	for (i = 0; i < t->_bench_threads; i++) {
		bi[i].index = i;
		bi[i].t = t;
		bi[i].key_tbl = t->_key_tbl;
		bi[i].nh_tbl = t->_nh_tbl;
		bi[i].done = 0;
		CPU_ZERO(&cpuset);
		if (t->_skip_smt) {
			cpu = i * 2;
			if (cpu >= t->_ncpus)
				cpu = cpu % t->_ncpus + 1;
		} else
			cpu = i;
		bi[i].cpu = cpu;
		if (pthread_create(&bi[i].td, NULL, bench_trampoline,
		    (void *) &bi[i]) == -1)
			err(EX_OSERR, "Can't start RX threads");
		CPU_SET(cpu, &cpuset);
		if (pthread_setaffinity_np(bi[i].td, sizeof(cpuset),
		    &cpuset) != 0)
			err(EX_OSERR, "pthread_setaffinity_np() failed");
	}

	usleep(10000);

	t->_bench_active = 1;
	sleep(10);
	t->_bench_active = 0;

	do {
		usleep(10000);
		for (i = 0; i < t->_bench_threads; i++)
			if (bi[i].done == 0)
				break;
	} while (i < t->_bench_threads);

	sa << "# " << t->class_name() << " (DIR-" << DIRECT_BITS << "-" <<
	    SECONDARY_BITS << "), ";
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

	sa << "# thread CPU time(s) ML MLps ";
	for (int j = 0; j < PMC_COUNTERS; j++) {
		sa << "M" << pmc_names[j] << " ";
		sa << "M" << pmc_names[j] << "/s ";
	}
	sa << "\n";

	for (i = 0; i < t->_bench_threads; i++) {
		time_ms = bi[i].t_len.sec() * 1000 + bi[i].t_len.usec() / 1000;
		sa << i << " ";
		sa << bi[i].cpu << " ";
		sa << bi[i].t_len << " ";
		sa << bi[i].lookups / 1000000.0 << " ";
		sa << bi[i].lookups / 1000.0 / time_ms << " ";
		for (int j = 0; j < PMC_COUNTERS; j++) {
			sa << bi[i].pmc[j] / 1000000.0 << " ";
			sa << bi[i].pmc[j] / 1000.0 / time_ms << " ";
		}
		sa << "\n";
	}

	t_len = bi[0].t_len;
	lookups = bi[0].lookups;
	pmc = bi[0].pmc[0];
	for (i = 1; i < t->_bench_threads; i++) {
		t_len += bi[i].t_len;
		lookups += bi[i].lookups;
		pmc += bi[i].pmc[0];
	}
	time_ms = t_len.sec() * 1000 + t_len.usec() / 1000;
	time_ms /= t->_bench_threads;
	klps = lookups / time_ms;

	sa << "# System: " << t->_bench_threads << " ";
	sa << t_len / t->_bench_threads << " ";
	sa << lookups / 1000000.0 << " ";
	sa << lookups / 1000.0 / time_ms << " ";
	sa << pmc / 1000000.0 << " ";
	sa << pmc / 1000.0 / time_ms << " ";
	sa << "\n";

	sa << "# Summary: ";
	sa << klps / 1000.0 << " MLps total, ";
	sa << klps / 1000.0 / t->_bench_threads << " MLps per core.\n";
	sa << "# " << pmc * 1.0 / lookups << " ";
	sa << pmc_names[0] << " / lookup\n";

	return (sa.take_string());
}


#define	BENCH_LOOP 65536

uint64_t
DirectIPLookup::bench_seq(uint32_t *key_tbl, uint16_t *nh_tbl, uint32_t offset)
{
	int nh = 0;
	uint32_t *key_ptr;
	uint16_t *nh_ptr;
	size_t size = 0;
	int i;

#define SEQ_STAGE							\
	do {								\
		nh = lookup_nexthop(*key_ptr++ + (nh >> 15));		\
		*nh_ptr++ = nh;						\
	} while (0)

	do {
	    for (i = 0; i < BENCH_LOOP; i++) {
		key_ptr = &key_tbl[offset];
		nh_ptr = &nh_tbl[offset];
		offset += 8;
		if (offset >= _test_blk)
			offset = 0;
		/* Manual unrolling for better throughput */
		SEQ_STAGE; SEQ_STAGE; SEQ_STAGE; SEQ_STAGE;
		SEQ_STAGE; SEQ_STAGE; SEQ_STAGE; SEQ_STAGE;
		size += 8;
	    }
	} while (_bench_active);

	return (size);
}


uint64_t
DirectIPLookup::bench_rnd(uint32_t *key_tbl, uint16_t *nh_tbl, uint32_t offset)
{
	uint32_t *key_ptr;
	uint16_t *nh_ptr;
	size_t size = 0;
	int i;

#define RND_STAGE do {*nh_ptr++ = lookup_nexthop(*key_ptr++);} while (0)

	do {
	    for (i = 0; i < BENCH_LOOP; i++) {
		key_ptr = &key_tbl[offset];
		nh_ptr = &nh_tbl[offset];
		offset += 8;
		if (offset >= _test_blk)
			offset = 0;
		/* Manual unrolling for better throughput */
		RND_STAGE; RND_STAGE; RND_STAGE; RND_STAGE;
		RND_STAGE; RND_STAGE; RND_STAGE; RND_STAGE;
		size += 8;
	    }
	} while (_bench_active);

	return (size);
}


uint64_t
DirectIPLookup::bench_rep(uint32_t *key_tbl, uint16_t *nh_tbl, uint32_t offset)
{
	uint32_t *key_ptr;
	uint16_t *nh_ptr;
	size_t size = 0;
	int i;

	do {
	    for (i = 0; i < BENCH_LOOP; i++) {
		key_ptr = &key_tbl[offset];
		nh_ptr = &nh_tbl[offset];
		offset += 1; /* Reuse same key 8 times */
		if (offset >= _test_blk - 8)
			offset = 0;
		/* Manual unrolling for better throughput */
		RND_STAGE; RND_STAGE; RND_STAGE; RND_STAGE;
		RND_STAGE; RND_STAGE; RND_STAGE; RND_STAGE;
		size += 8;
	    }
	} while (_bench_active);

	return (size);
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(BSDIPLookup)
EXPORT_ELEMENT(DirectIPLookup)
