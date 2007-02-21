/*-
 * Copyright (C) 2006 Jason Evans <jasone@FreeBSD.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *******************************************************************************
 *
 * Following is a brief list of features that distinguish this malloc
 * implementation:
 *
 *   + Multiple arenas are used if there are multiple CPUs, which reduces lock
 *     contention and cache sloshing.
 *
 *   + Cache line sharing between arenas is avoided for internal data
 *     structures.
 *
 *   + Memory is managed in chunks and runs, rather than as individual pages.
 *
 *   + Data structures for huge allocations are stored separately from
 *     allocations, which reduces thrashing during low memory conditions.
 *
 *******************************************************************************
 */

/*
 *******************************************************************************
 *
 * Ring macros.
 *
 *******************************************************************************
 */

/* Ring definitions. */
#define	qr(a_type) struct {						\
	a_type *qre_next;						\
	a_type *qre_prev;						\
}

#define	qr_initializer {NULL, NULL}

/* Ring functions. */
#define	qr_new(a_qr, a_field) do {					\
	(a_qr)->a_field.qre_next = (a_qr);				\
	(a_qr)->a_field.qre_prev = (a_qr);				\
} while (0)

#define	qr_next(a_qr, a_field) ((a_qr)->a_field.qre_next)

#define	qr_prev(a_qr, a_field) ((a_qr)->a_field.qre_prev)

#define	qr_before_insert(a_qrelm, a_qr, a_field) do {			\
	(a_qr)->a_field.qre_prev = (a_qrelm)->a_field.qre_prev;		\
	(a_qr)->a_field.qre_next = (a_qrelm);				\
	(a_qr)->a_field.qre_prev->a_field.qre_next = (a_qr);		\
	(a_qrelm)->a_field.qre_prev = (a_qr);				\
} while (0)

#define	qr_after_insert(a_qrelm, a_qr, a_field) do {			\
	(a_qr)->a_field.qre_next = (a_qrelm)->a_field.qre_next;		\
	(a_qr)->a_field.qre_prev = (a_qrelm);				\
	(a_qr)->a_field.qre_next->a_field.qre_prev = (a_qr);		\
	(a_qrelm)->a_field.qre_next = (a_qr);				\
} while (0)

#define	qr_meld(a_qr_a, a_qr_b, a_type, a_field) do {			\
	a_type *t;							\
	(a_qr_a)->a_field.qre_prev->a_field.qre_next = (a_qr_b);	\
	(a_qr_b)->a_field.qre_prev->a_field.qre_next = (a_qr_a);	\
	t = (a_qr_a)->a_field.qre_prev;					\
	(a_qr_a)->a_field.qre_prev = (a_qr_b)->a_field.qre_prev;	\
	(a_qr_b)->a_field.qre_prev = t;					\
} while (0)

/* qr_meld() and qr_split() are functionally equivalent, so there's no need to
 * have two copies of the code. */
#define	qr_split(a_qr_a, a_qr_b, a_type, a_field)			\
	qr_meld((a_qr_a), (a_qr_b), a_type, a_field)

#define	qr_remove(a_qr, a_field) do {					\
	(a_qr)->a_field.qre_prev->a_field.qre_next			\
	    = (a_qr)->a_field.qre_next;					\
	(a_qr)->a_field.qre_next->a_field.qre_prev			\
	    = (a_qr)->a_field.qre_prev;					\
	(a_qr)->a_field.qre_next = (a_qr);				\
	(a_qr)->a_field.qre_prev = (a_qr);				\
} while (0)

#define	qr_foreach(var, a_qr, a_field)					\
	for ((var) = (a_qr);						\
	    (var) != NULL;						\
	    (var) = (((var)->a_field.qre_next != (a_qr))		\
	    ? (var)->a_field.qre_next : NULL))

#define	qr_reverse_foreach(var, a_qr, a_field)				\
	for ((var) = ((a_qr) != NULL) ? qr_prev(a_qr, a_field) : NULL;	\
	    (var) != NULL;						\
	    (var) = (((var) != (a_qr))					\
	    ? (var)->a_field.qre_prev : NULL))

/******************************************************************************/

/* 
 * In order to disable various extra features that may have negative
 * performance impacts, (assertions, expanded statistics, redzones), define
 * NO_MALLOC_EXTRAS.
 */
/* #define NO_MALLOC_EXTRAS */

#ifndef NO_MALLOC_EXTRAS
#  define MALLOC_DEBUG
#endif

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/lib/libc/stdlib/malloc.c,v 1.114 2006/03/20 04:05:05 jasone Exp $");

#include "libc_private.h"
#ifdef MALLOC_DEBUG
#  define _LOCK_DEBUG
#endif
#include "spinlock.h"
#include "namespace.h"
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stddef.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/ktrace.h> /* Must come after several other sys/ includes. */

#include <machine/atomic.h>
#include <machine/cpufunc.h>
#include <machine/vmparam.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "un-namespace.h"

/*
 * Calculate statistics that can be used to get an idea of how well caching is
 * working.
 */
#ifndef NO_MALLOC_EXTRAS
#  define MALLOC_STATS
#endif

#ifndef MALLOC_DEBUG
#  ifndef NDEBUG
#    define NDEBUG
#  endif
#endif
#include <assert.h>

#ifdef MALLOC_DEBUG
   /* Disable inlining to make debugging easier. */
#  define inline
#endif

/* Size of stack-allocated buffer passed to strerror_r(). */
#define	STRERROR_BUF 64

/* Minimum alignment of allocations is 2^QUANTUM_2POW_MIN bytes. */
#ifdef __i386__
#  define QUANTUM_2POW_MIN	4
#  define SIZEOF_PTR		4
#  define USE_BRK
#endif
#ifdef __ia64__
#  define QUANTUM_2POW_MIN	4
#  define SIZEOF_PTR		8
#  define NO_TLS
#endif
#ifdef __alpha__
#  define QUANTUM_2POW_MIN	4
#  define SIZEOF_PTR		8
#  define NO_TLS
#endif
#ifdef __sparc64__
#  define QUANTUM_2POW_MIN	4
#  define SIZEOF_PTR		8
#  define NO_TLS
#endif
#ifdef __amd64__
#  define QUANTUM_2POW_MIN	4
#  define SIZEOF_PTR		8
#endif
#ifdef __arm__
#  define QUANTUM_2POW_MIN	3
#  define SIZEOF_PTR		4
#  define USE_BRK
#  define NO_TLS
#endif
#ifdef __powerpc__
#  define QUANTUM_2POW_MIN	4
#  define SIZEOF_PTR		4
#  define USE_BRK
#endif

/* We can't use TLS in non-PIC programs, since TLS relies on loader magic. */
#if (!defined(PIC) && !defined(NO_TLS))
#  define NO_TLS
#endif

/*
 * Size and alignment of memory chunks that are allocated by the OS's virtual
 * memory system.
 *
 * chunksize limits:
 *
 *   2^(pagesize_2pow - 1 + RUN_MIN_REGS_2POW) <= chunk_size <= 2^28
 */
#define	CHUNK_2POW_DEFAULT	21
#define	CHUNK_2POW_MAX		28

/*
 * Maximum size of L1 cache line.  This is used to avoid cache line aliasing,
 * so over-estimates are okay (up to a point), but under-estimates will
 * negatively affect performance.
 */
#define	CACHELINE_2POW 6
#define	CACHELINE ((size_t)(1 << CACHELINE_2POW))

/* Minimum size class that is a power of 2, and smaller than the quantum. */
#define TINY_MIN_2POW 1
#define TINY_MIN (1 << TINY_MIN_2POW)

/*
 * Maximum size class that is a multiple of the quantum, but not (necessarily)
 * a power of 2.  Above this size, allocations are rounded up to the nearest
 * power of 2.
 */
#define SMALL_MAX_2POW_DEFAULT 9
#define SMALL_MAX_DEFAULT (1 << SMALL_MAX_2POW_DEFAULT)

/*
 * Minimum number of regions that must fit into a run that serves quantum-size
 * bin allocations.
 *
 * Note that if this is set too low, space will be wasted if there are size
 * classes that are small enough that RUN_MIN_REGS regions don't fill a page.
 * If this is set too high, then the overhead of searching through the bitmap
 * that tracks region usage will become excessive.
 */
#define RUN_MIN_REGS_2POW 10
#define RUN_MIN_REGS (1 << RUN_MIN_REGS_2POW)

/*
 * Maximum number of pages for a run that is used for bin allocations.
 *
 * Note that if this is set too low, then fragmentation for the largest bin
 * size classes will be high.  If this is set too high, then even small
 * programs will often have to allocate more than two chunks early on.
 */
#define RUN_MAX_PAGES_2POW 4
#define RUN_MAX_PAGES (1 << RUN_MAX_PAGES_2POW)

/******************************************************************************/

/*
 * Mutexes based on spinlocks.  We can't use normal pthread mutexes, because
 * they require malloc()ed memory.
 */
typedef struct {
	spinlock_t	lock;
} malloc_mutex_t;

static bool malloc_initialized = false;

/******************************************************************************/
/*
 * Statistics data structures.
 */

#ifdef MALLOC_STATS

typedef struct malloc_bin_stats_s malloc_bin_stats_t;
struct malloc_bin_stats_s {
	/*
	 * Number of allocation requests that corresponded to the size of this
	 * bin.
	 */
	uint64_t	nrequests;

	/* Total number of runs created for this bin's size class. */
	uint64_t	nruns;

	/*
	 * Total number of run promotions/demotions for this bin's size class.
	 */
	uint64_t	npromote;
	uint64_t	ndemote;

	/* High-water mark for this bin. */
	unsigned long	highruns;

	/* Current number of runs in this bin. */
	unsigned long	curruns;
};

typedef struct arena_stats_s arena_stats_t;
struct arena_stats_s {
	/* Number of times each function was called. */
	uint64_t	nmalloc;
	uint64_t	npalloc;
	uint64_t	ncalloc;
	uint64_t	ndalloc;
	uint64_t	nralloc;
	uint64_t	nmadvise;
};

typedef struct chunk_stats_s chunk_stats_t;
struct chunk_stats_s {
	/* Number of chunks that were allocated. */
	uint64_t	nchunks;

	/* High-water mark for number of chunks allocated. */
	unsigned long	highchunks;

	/*
	 * Current number of chunks allocated.  This value isn't maintained for
	 * any other purpose, so keep track of it in order to be able to set
	 * highchunks.
	 */
	unsigned long	curchunks;
};

#endif /* #ifdef MALLOC_STATS */

/******************************************************************************/
/*
 * Chunk data structures.
 */

/* Tree of chunks. */
typedef struct chunk_node_s chunk_node_t;
struct chunk_node_s {
	/* Linkage for the chunk tree. */
	RB_ENTRY(chunk_node_s) link;

	/*
	 * Pointer to the chunk that this tree node is responsible for.  In some
	 * (but certainly not all) cases, this data structure is placed at the
	 * beginning of the corresponding chunk, so this field may point to this
	 * node.
	 */
	void	*chunk;

	/* Total chunk size. */
	size_t	size;
};
typedef struct chunk_tree_s chunk_tree_t;
RB_HEAD(chunk_tree_s, chunk_node_s);

/******************************************************************************/
/*
 * Arena data structures.
 */

typedef struct arena_s arena_t;
typedef struct arena_bin_s arena_bin_t;

typedef struct arena_chunk_map_s arena_chunk_map_t;
struct arena_chunk_map_s {
	bool		free:1;
	bool		large:1;
	unsigned	npages:15; /* Limiting factor for CHUNK_2POW_MAX. */
	unsigned	pos:15;
};

/* Arena chunk header. */
typedef struct arena_chunk_s arena_chunk_t;
struct arena_chunk_s {
	/* Arena that owns the chunk. */
	arena_t *arena;

	/* Linkage for the arena's chunk tree. */
	RB_ENTRY(arena_chunk_s) link;

	/*
	 * Number of pages in use.  This is maintained in order to make
	 * detection of empty chunks fast.
	 */
	uint32_t pages_used;

	/*
	 * Array of counters that keeps track of how many free runs of each
	 * size are available in this chunk.  This table is sized at compile
	 * time, which is wasteful.  However, due to unrelated rounding, this
	 * doesn't actually waste any otherwise useful space.
	 *
	 *   index == 2^n pages
	 *
	 *   index | npages
	 *   ------+-------
	 *       0 |      1
	 *       1 |      2
	 *       2 |      4
	 *       3 |      8
	 *         :
	 */
	uint32_t nfree_runs[CHUNK_2POW_MAX/* - PAGE_SHIFT */];

	/* Map of pages within chunk that keeps track of free/large/small. */
	arena_chunk_map_t map[1]; /* Dynamically sized. */
};
typedef struct arena_chunk_tree_s arena_chunk_tree_t;
RB_HEAD(arena_chunk_tree_s, arena_chunk_s);

typedef struct arena_run_s arena_run_t;
struct arena_run_s {
#ifdef MALLOC_DEBUG
	uint32_t		magic;
#  define ARENA_RUN_MAGIC 0x384adf93
#endif

	/* Linkage for run rings. */
	qr(arena_run_t)	link;

	/* Bin this run is associated with. */
	arena_bin_t	*bin;

	/* Bitmask of in-use regions (0: in use, 1: free). */
#define REGS_MASK_NELMS							\
	((1 << (RUN_MIN_REGS_2POW + 1)) / (sizeof(unsigned) << 3))
	unsigned	regs_mask[REGS_MASK_NELMS];

	/* Index of first element that might have a free region. */
	unsigned	regs_minelm;

	/* Number of free regions in run. */
	unsigned	nfree:(RUN_MIN_REGS_2POW + 1);

	/*
	 * Current quartile for this run, one of: {RUN_QEMPTY, RUN_Q0, RUN_25,
	 * RUN_Q50, RUN_Q75, RUN_Q100}.
	 */
#define RUN_QEMPTY	0
#define RUN_Q0		1
#define RUN_Q25		2
#define RUN_Q50		3
#define RUN_Q75		4
#define RUN_Q100	5
	unsigned	quartile:3;

	/*
	 * Limits on the number of free regions for the fullness quartile this
	 * run is currently in.  If nfree goes outside these limits, the run
	 * is moved to a different fullness quartile.
	 */
	unsigned	free_max:(RUN_MIN_REGS_2POW + 1);
	unsigned	free_min:(RUN_MIN_REGS_2POW + 1);
};

struct arena_bin_s {
	/*
	 * Current run being used to service allocations of this bin's size
	 * class.
	 */
	arena_run_t	*runcur;

	/*
	 * Links into rings of runs, of various fullnesses (names indicate
	 * approximate lower bounds).  A new run conceptually starts off in
	 * runsempty, and it isn't inserted into the runs0 ring until it
	 * reaches 25% full (hysteresis mechanism).  For the run to be moved
	 * again, it must become either empty or 50% full.  Thus, each ring
	 * contains runs that are within 50% above the advertised fullness for
	 * the ring.  This provides a low-overhead mechanism for segregating
	 * runs into approximate fullness classes.
	 *
	 * Conceptually, there is a runs100 that contains completely full runs.
	 * Since we don't need to search for these runs though, no runs100 ring
	 * is actually maintained.
	 *
	 * These rings are useful when looking for an existing run to use when
	 * runcur is no longer usable.  We look for usable runs in the
	 * following order:
	 *
	 *   1) runs50
	 *   2) runs25
	 *   3) runs0
	 *   4) runs75
	 *
	 * runs75 isn't a good place to look, because it contains runs that
	 * may be nearly completely full.  Still, we look there as a last
	 * resort in order to avoid allocating a new run if at all possible.
	 */
	/* arena_run_t	runsempty;  0% <= fullness <   25% */
	arena_run_t	runs0;  /*  0% <  fullness <   50% */
	arena_run_t	runs25; /* 25% <  fullness <   75% */
	arena_run_t	runs50; /* 50% <  fullness <  100% */
	arena_run_t	runs75; /* 75% <  fullness <  100% */
	/* arena_run_t	runs100;          fullness == 100% */

	/* Size of regions in a run for this bin's size class. */
	size_t		reg_size;

	/* Total size of a run for this bin's size class. */
	size_t		run_size;

	/* Total number of regions in a run for this bin's size class. */
	uint32_t	nregs;

	/* Offset of first region in a run for this bin's size class. */
	uint32_t	reg0_offset;

#ifdef MALLOC_STATS
	/* Bin statistics. */
	malloc_bin_stats_t stats;
#endif
};

struct arena_s {
#ifdef MALLOC_DEBUG
	uint32_t		magic;
#  define ARENA_MAGIC 0x947d3d24
#endif

	/* All operations on this arena require that mtx be locked. */
	malloc_mutex_t		mtx;

#ifdef MALLOC_STATS
	/* Total byte count of allocated memory, not including overhead. */
	size_t			allocated;

	arena_stats_t		stats;
#endif

	/*
	 * Tree of chunks this arena manages.
	 */
	arena_chunk_tree_t	chunks;

	/*
	 * bins is used to store rings of free regions of the following sizes,
	 * assuming a 16-byte quantum, 4kB pagesize, and default MALLOC_OPTIONS.
	 *
	 *   bins[i] | size |
	 *   --------+------+
	 *        0  |    2 |
	 *        1  |    4 |
	 *        2  |    8 |
	 *   --------+------+
	 *        3  |   16 |
	 *        4  |   32 |
	 *        5  |   48 |
	 *        6  |   64 |
	 *           :      :
	 *           :      :
	 *       33  |  496 |
	 *       34  |  512 |
	 *   --------+------+
	 *       35  | 1024 |
	 *       36  | 2048 |
	 *   --------+------+
	 */
	arena_bin_t		bins[1]; /* Dynamically sized. */
};

/******************************************************************************/
/*
 * Data.
 */

/* Used as a special "nil" return value for malloc(0). */
static int		nil;

/* Number of CPUs. */
static unsigned		ncpus;

/* VM page size. */
static unsigned		pagesize;
static unsigned		pagesize_2pow;

/* Various bin-related settings. */
static size_t		bin_maxclass; /* Max size class for bins. */
static unsigned		ntbins; /* Number of (2^n)-spaced tiny bins. */
static unsigned		nqbins; /* Number of quantum-spaced bins. */
static unsigned		npbins; /* Number of (2^n)-spaced bins. */
static size_t		small_min;
static size_t		small_max;

/* Various quantum-related settings. */
static size_t		quantum;
static size_t		quantum_mask; /* (quantum - 1). */

/* Various chunk-related settings. */
static size_t		chunk_size;
static size_t		chunk_size_mask; /* (chunk_size - 1). */
static size_t		arena_maxclass; /* Max size class for arenas. */
static unsigned		arena_chunk_maplen;

/********/
/*
 * Chunks.
 */

/* Protects chunk-related data structures. */
static malloc_mutex_t	chunks_mtx;

/* Tree of chunks that are stand-alone huge allocations. */
static chunk_tree_t	huge;

#ifdef USE_BRK
/*
 * Try to use brk for chunk-size allocations, due to address space constraints.
 */
/* Result of first sbrk(0) call. */
static void		*brk_base;
/* Current end of brk, or ((void *)-1) if brk is exhausted. */
static void		*brk_prev;
/* Upper limit on brk addresses (may be an over-estimate). */
static void		*brk_max;
#endif

#ifdef MALLOC_STATS
/*
 * Byte counters for allocated/total space used by the chunks in the huge
 * allocations tree.
 */
static uint64_t		huge_nmalloc;
static uint64_t		huge_ndalloc;
static size_t		huge_allocated;
#endif

/*
 * Tree of chunks that were previously allocated.  This is used when allocating
 * chunks, in an attempt to re-use address space.
 */
static chunk_tree_t	old_chunks;

/****************************/
/*
 * base (internal allocation).
 */

/*
 * Current chunk that is being used for internal memory allocations.  This
 * chunk is carved up in cacheline-size quanta, so that there is no chance of
 * false cache line sharing. 
 * */
static void		*base_chunk;
static void		*base_next_addr;
static void		*base_past_addr; /* Addr immediately past base_chunk. */
static chunk_node_t	*base_chunk_nodes; /* LIFO cache of chunk nodes. */
static malloc_mutex_t	base_mtx;
#ifdef MALLOC_STATS
static uint64_t		base_total;
#endif

/********/
/*
 * Arenas.
 */

/* 
 * Arenas that are used to service external requests.  Not all elements of the
 * arenas array are necessarily used; arenas are created lazily as needed.
 */
static arena_t		**arenas;
static unsigned		narenas;
#ifndef NO_TLS
static unsigned		next_arena;
#endif
static malloc_mutex_t	arenas_mtx; /* Protects arenas initialization. */

#ifndef NO_TLS
/*
 * Map of pthread_self() --> arenas[???], used for selecting an arena to use
 * for allocations.
 */
static __thread arena_t *arenas_map;
#endif

#ifdef MALLOC_STATS
/* Chunk statistics. */
static chunk_stats_t	stats_chunks;
#endif

/*******************************/
/*
 * Runtime configuration options.
 */
const char	*_malloc_options;

#ifndef NO_MALLOC_EXTRAS
static bool	opt_abort = true;
static bool	opt_junk = true;
#else
static bool	opt_abort = false;
static bool	opt_junk = false;
#endif
static bool	opt_hint = false;
static bool	opt_print_stats = false;
static size_t	opt_quantum_2pow = QUANTUM_2POW_MIN;
static size_t	opt_small_max_2pow = SMALL_MAX_2POW_DEFAULT;
static size_t	opt_chunk_2pow = CHUNK_2POW_DEFAULT;
static bool	opt_utrace = false;
static bool	opt_sysv = false;
static bool	opt_xmalloc = false;
static bool	opt_zero = false;
static int32_t	opt_narenas_lshift = 0;

typedef struct {
	void	*p;
	size_t	s;
	void	*r;
} malloc_utrace_t;

#define	UTRACE(a, b, c)							\
	if (opt_utrace) {						\
		malloc_utrace_t ut = {a, b, c};				\
		utrace(&ut, sizeof(ut));				\
	}

/******************************************************************************/
/*
 * Begin function prototypes for non-inline static functions.
 */

static void	malloc_mutex_init(malloc_mutex_t *a_mutex);
static void	wrtmessage(const char *p1, const char *p2, const char *p3,
		const char *p4);
static void	malloc_printf(const char *format, ...);
static void	*base_alloc(size_t size);
static chunk_node_t *base_chunk_node_alloc(void);
static void	base_chunk_node_dealloc(chunk_node_t *node);
#ifdef MALLOC_STATS
static void	stats_print(arena_t *arena);
#endif
static void	*pages_map(void *addr, size_t size);
static void	pages_unmap(void *addr, size_t size);
static void	*chunk_alloc(size_t size);
static void	chunk_dealloc(void *chunk, size_t size);
static void	arena_run_split(arena_t *arena, arena_run_t *run, bool large,
    size_t size);
static arena_chunk_t *arena_chunk_alloc(arena_t *arena);
static void	arena_chunk_dealloc(arena_chunk_t *chunk);
static void	arena_bin_run_refile(arena_t *arena, arena_bin_t *bin,
    arena_run_t *run, size_t size, bool promote);
static arena_run_t *arena_run_alloc(arena_t *arena, bool large, size_t size);
static void	arena_run_dalloc(arena_t *arena, arena_run_t *run, size_t size);
static arena_run_t *arena_bin_nonfull_run_get(arena_t *arena, arena_bin_t *bin,
    size_t size);
static void *arena_bin_malloc_hard(arena_t *arena, arena_bin_t *bin,
    size_t size);
static void	*arena_malloc(arena_t *arena, size_t size);
static void	*arena_ralloc(arena_t *arena, void *ptr, size_t size,
    size_t oldsize);
static size_t	arena_salloc(arena_t *arena, void *ptr);
static void	arena_dalloc(arena_t *arena, void *ptr);
#ifdef MALLOC_STATS
static size_t	arena_allocated(arena_t *arena);
#endif
static bool	arena_new(arena_t *arena);
static arena_t	*arenas_extend(unsigned ind);
#ifndef NO_TLS
static arena_t	*choose_arena_hard(void);
#endif
static void	*huge_malloc(size_t size);
static void	*huge_ralloc(void *ptr, size_t size, size_t oldsize);
static void	huge_dalloc(void *ptr);
static void	*imalloc(arena_t *arena, size_t size);
static void	*ipalloc(arena_t *arena, size_t alignment, size_t size);
static void	*icalloc(arena_t *arena, size_t size);
static void	*iralloc(arena_t *arena, void *ptr, size_t size);
static size_t	isalloc(void *ptr);
static void	idalloc(void *ptr);
#ifdef MALLOC_STATS
static void	istats(size_t *allocated, size_t *total);
#endif
static void	malloc_print_stats(void);
static bool	malloc_init_hard(void);

/*
 * End function prototypes.
 */
/******************************************************************************/
/*
 * Begin mutex.
 */

static void
malloc_mutex_init(malloc_mutex_t *a_mutex)
{
	static const spinlock_t lock = _SPINLOCK_INITIALIZER;

	a_mutex->lock = lock;
}

static inline void
malloc_mutex_lock(malloc_mutex_t *a_mutex)
{

	if (__isthreaded)
		_SPINLOCK(&a_mutex->lock);
}

static inline void
malloc_mutex_unlock(malloc_mutex_t *a_mutex)
{

	if (__isthreaded)
		_SPINUNLOCK(&a_mutex->lock);
}

/*
 * End mutex.
 */
/******************************************************************************/
/*
 * Begin Utility functions/macros.
 */

/* Return the chunk address for allocation address a. */
#define	CHUNK_ADDR2BASE(a)						\
	((void *)((uintptr_t)(a) & ~chunk_size_mask))

/* Return the chunk offset of address a. */
#define	CHUNK_ADDR2OFFSET(a)						\
	((size_t)((uintptr_t)(a) & chunk_size_mask))

/* Return the smallest chunk multiple that is >= s. */
#define	CHUNK_CEILING(s)						\
	(((s) + chunk_size_mask) & ~chunk_size_mask)

/* Return the smallest cacheline multiple that is >= s. */
#define	CACHELINE_CEILING(s)						\
	(((s) + (CACHELINE - 1)) & ~(CACHELINE - 1))

/* Return the smallest quantum multiple that is >= a. */
#define	QUANTUM_CEILING(a)						\
	(((a) + quantum_mask) & ~quantum_mask)

/* Compute the smallest power of 2 that is >= x. */
static inline size_t
pow2_ceil(size_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
#if (SIZEOF_PTR == 8)
	x |= x >> 32;
#endif
	x++;
	return (x);
}

static void
wrtmessage(const char *p1, const char *p2, const char *p3, const char *p4)
{

	_write(STDERR_FILENO, p1, strlen(p1));
	_write(STDERR_FILENO, p2, strlen(p2));
	_write(STDERR_FILENO, p3, strlen(p3));
	_write(STDERR_FILENO, p4, strlen(p4));
}

void	(*_malloc_message)(const char *p1, const char *p2, const char *p3,
	    const char *p4) = wrtmessage;

/*
 * Print to stderr in such a way as to (hopefully) avoid memory allocation.
 */
static void
malloc_printf(const char *format, ...)
{
	char buf[4096];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	_malloc_message(buf, "", "", "");
}

/******************************************************************************/

static void *
base_alloc(size_t size)
{
	void *ret;
	size_t csize;

	/* Round size up to nearest multiple of the cacheline size. */
	csize = CACHELINE_CEILING(size);

	malloc_mutex_lock(&base_mtx);

	/* Make sure there's enough space for the allocation. */
	if ((uintptr_t)base_next_addr + csize > (uintptr_t)base_past_addr) {
		void *tchunk;
		size_t alloc_size;

		/*
		 * If chunk_size and opt_ndelay are sufficiently small and
		 * large, respectively, it's possible for an allocation request
		 * to exceed a single chunk here.  Deal with this, but don't
		 * worry about internal fragmentation.
		 */

		if (csize <= chunk_size)
			alloc_size = chunk_size;
		else
			alloc_size = CHUNK_CEILING(csize);

		tchunk = chunk_alloc(alloc_size);
		if (tchunk == NULL) {
			ret = NULL;
			goto RETURN;
		}
		base_chunk = tchunk;
		base_next_addr = (void *)base_chunk;
		base_past_addr = (void *)((uintptr_t)base_chunk + alloc_size);
#ifdef MALLOC_STATS
		base_total += alloc_size;
#endif
	}

	/* Allocate. */
	ret = base_next_addr;
	base_next_addr = (void *)((uintptr_t)base_next_addr + csize);

RETURN:
	malloc_mutex_unlock(&base_mtx);
	return (ret);
}

static chunk_node_t *
base_chunk_node_alloc(void)
{
	chunk_node_t *ret;

	malloc_mutex_lock(&base_mtx);
	if (base_chunk_nodes != NULL) {
		ret = base_chunk_nodes;
		base_chunk_nodes = *(chunk_node_t **)ret;
		malloc_mutex_unlock(&base_mtx);
	} else {
		malloc_mutex_unlock(&base_mtx);
		ret = (chunk_node_t *)base_alloc(sizeof(chunk_node_t));
	}

	return (ret);
}

static void
base_chunk_node_dealloc(chunk_node_t *node)
{

	malloc_mutex_lock(&base_mtx);
	*(chunk_node_t **)node = base_chunk_nodes;
	base_chunk_nodes = node;
	malloc_mutex_unlock(&base_mtx);
}

/******************************************************************************/

#ifdef MALLOC_STATS
static void
stats_print(arena_t *arena)
{
	unsigned i;
	int gap_start;

	malloc_printf("calls:\n");
	malloc_printf(" %12s %12s %12s %12s %12s %12s\n", "nmalloc", "npalloc",
	    "ncalloc", "ndalloc", "nralloc", "nmadvise");
	malloc_printf(" %12llu %12llu %12llu %12llu %12llu %12llu\n",
	    arena->stats.nmalloc, arena->stats.npalloc, arena->stats.ncalloc,
	    arena->stats.ndalloc, arena->stats.nralloc, arena->stats.nmadvise);

	malloc_printf("bins:\n");
	malloc_printf("%13s %1s %4s %5s %8s %9s %5s %6s %7s %6s %6s\n",
	    "bin", "", "size", "nregs", "run_size", "nrequests", "nruns",
	    "hiruns", "curruns", "npromo", "ndemo");
	for (i = 0, gap_start = -1; i < ntbins + nqbins + npbins; i++) {
		if (arena->bins[i].stats.nrequests == 0) {
			if (gap_start == -1)
				gap_start = i;
		} else {
			if (gap_start != -1) {
				if (i > gap_start + 1) {
					/* Gap of more than one size class. */
					malloc_printf("[%u..%u]\n",
					    gap_start, i - 1);
				} else {
					/* Gap of one size class. */
					malloc_printf("[%u]\n", gap_start);
				}
				gap_start = -1;
			}
			malloc_printf(
			    "%13u %1s %4u %5u %8u %9llu %5llu"
			    " %6lu %7lu %6llu %6llu\n",
			    i,
			    i < ntbins ? "T" : i < ntbins + nqbins ? "Q" : "P",
			    arena->bins[i].reg_size,
			    arena->bins[i].nregs,
			    arena->bins[i].run_size,
			    arena->bins[i].stats.nrequests,
			    arena->bins[i].stats.nruns,
			    arena->bins[i].stats.highruns,
			    arena->bins[i].stats.curruns,
			    arena->bins[i].stats.npromote,
			    arena->bins[i].stats.ndemote);
		}
	}
	if (gap_start != -1) {
		if (i > gap_start + 1) {
			/* Gap of more than one size class. */
			malloc_printf("[%u..%u]\n", gap_start, i - 1);
		} else {
			/* Gap of one size class. */
			malloc_printf("[%u]\n", gap_start);
		}
	}
}
#endif

/*
 * End Utility functions/macros.
 */
/******************************************************************************/
/*
 * Begin chunk management functions.
 */

static inline int
chunk_comp(chunk_node_t *a, chunk_node_t *b)
{

	assert(a != NULL);
	assert(b != NULL);

	if ((uintptr_t)a->chunk < (uintptr_t)b->chunk)
		return (-1);
	else if (a->chunk == b->chunk)
		return (0);
	else
		return (1);
}

/* Generate red-black tree code for chunks. */
RB_GENERATE_STATIC(chunk_tree_s, chunk_node_s, link, chunk_comp);

static void *
pages_map(void *addr, size_t size)
{
	void *ret;

#ifdef USE_BRK
AGAIN:
#endif
	/*
	 * We don't use MAP_FIXED here, because it can cause the *replacement*
	 * of existing mappings, and we only want to create new mappings.
	 */
	ret = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
	    -1, 0);
	assert(ret != NULL);

	if (ret == MAP_FAILED)
		ret = NULL;
	else if (addr != NULL && ret != addr) {
		/*
		 * We succeeded in mapping memory, but not in the right place.
		 */
		if (munmap(ret, size) == -1) {
			char buf[STRERROR_BUF];

			strerror_r(errno, buf, sizeof(buf));
			malloc_printf("%s: (malloc) Error in munmap(): %s\n",
			    _getprogname(), buf);
			if (opt_abort)
				abort();
		}
		ret = NULL;
	}
#ifdef USE_BRK
	else if ((uintptr_t)ret >= (uintptr_t)brk_base
	    && (uintptr_t)ret < (uintptr_t)brk_max) {
		/*
		 * We succeeded in mapping memory, but at a location that could
		 * be confused with brk.  Leave the mapping intact so that this
		 * won't ever happen again, then try again.
		 */
		assert(addr == NULL);
		goto AGAIN;
	}
#endif

	assert(ret == NULL || (addr == NULL && ret != addr)
	    || (addr != NULL && ret == addr));
	return (ret);
}

static void
pages_unmap(void *addr, size_t size)
{

	if (munmap(addr, size) == -1) {
		char buf[STRERROR_BUF];

		strerror_r(errno, buf, sizeof(buf));
		malloc_printf("%s: (malloc) Error in munmap(): %s\n",
		    _getprogname(), buf);
		if (opt_abort)
			abort();
	}
}

static void *
chunk_alloc(size_t size)
{
	void *ret, *chunk;
	chunk_node_t *tchunk, *delchunk;

	assert(size != 0);
	assert(size % chunk_size == 0);

	malloc_mutex_lock(&chunks_mtx);

	if (size == chunk_size) {
		/*
		 * Check for address ranges that were previously chunks and try
		 * to use them.
		 */

		tchunk = RB_MIN(chunk_tree_s, &old_chunks);
		while (tchunk != NULL) {
			/* Found an address range.  Try to recycle it. */

			chunk = tchunk->chunk;
			delchunk = tchunk;
			tchunk = RB_NEXT(chunk_tree_s, &old_chunks, delchunk);

			/* Remove delchunk from the tree. */
			RB_REMOVE(chunk_tree_s, &old_chunks, delchunk);
			base_chunk_node_dealloc(delchunk);

#ifdef USE_BRK
			if ((uintptr_t)chunk >= (uintptr_t)brk_base
			    && (uintptr_t)chunk < (uintptr_t)brk_max) {
				/* Re-use a previously freed brk chunk. */
				ret = chunk;
				goto RETURN;
			}
#endif
			if ((ret = pages_map(chunk, size)) != NULL) {
				/* Success. */
				goto RETURN;
			}
		}

#ifdef USE_BRK
		/*
		 * Try to create chunk-size allocations in brk, in order to
		 * make full use of limited address space.
		 */
		if (brk_prev != (void *)-1) {
			void *brk_cur;
			intptr_t incr;

			/*
			 * The loop is necessary to recover from races with
			 * other threads that are using brk for something other
			 * than malloc.
			 */
			do {
				/* Get the current end of brk. */
				brk_cur = sbrk(0);

				/*
				 * Calculate how much padding is necessary to
				 * chunk-align the end of brk.
				 */
				incr = (char *)chunk_size
				    - (char *)CHUNK_ADDR2OFFSET(brk_cur);
				if (incr == chunk_size) {
					ret = brk_cur;
				} else {
					ret = (char *)brk_cur + incr;
					incr += chunk_size;
				}

				brk_prev = sbrk(incr);
				if (brk_prev == brk_cur) {
					/* Success. */
					goto RETURN;
				}
			} while (brk_prev != (void *)-1);
		}
#endif
	}

	/*
	 * Try to over-allocate, but allow the OS to place the allocation
	 * anywhere.  Beware of size_t wrap-around.
	 */
	if (size + chunk_size > size) {
		if ((ret = pages_map(NULL, size + chunk_size)) != NULL) {
			size_t offset = CHUNK_ADDR2OFFSET(ret);

			/*
			 * Success.  Clean up unneeded leading/trailing space.
			 */
			if (offset != 0) {
				/* Leading space. */
				pages_unmap(ret, chunk_size - offset);

				ret = (void *)((uintptr_t)ret + (chunk_size -
				    offset));

				/* Trailing space. */
				pages_unmap((void *)((uintptr_t)ret + size),
				    offset);
			} else {
				/* Trailing space only. */
				pages_unmap((void *)((uintptr_t)ret + size),
				    chunk_size);
			}
			goto RETURN;
		}
	}

	/* All strategies for allocation failed. */
	ret = NULL;
RETURN:
#ifdef MALLOC_STATS
	if (ret != NULL) {
		stats_chunks.nchunks += (size / chunk_size);
		stats_chunks.curchunks += (size / chunk_size);
	}
	if (stats_chunks.curchunks > stats_chunks.highchunks)
		stats_chunks.highchunks = stats_chunks.curchunks;
#endif
	malloc_mutex_unlock(&chunks_mtx);

	assert(CHUNK_ADDR2BASE(ret) == ret);
	return (ret);
}

static void
chunk_dealloc(void *chunk, size_t size)
{

	assert(chunk != NULL);
	assert(CHUNK_ADDR2BASE(chunk) == chunk);
	assert(size != 0);
	assert(size % chunk_size == 0);

	if (size == chunk_size) {
		chunk_node_t *node;

		node = base_chunk_node_alloc();

		malloc_mutex_lock(&chunks_mtx);
		if (node != NULL) {
			/*
			 * Create a record of this chunk before deallocating
			 * it, so that the address range can be recycled if
			 * memory usage increases later on.
			 */
			node->chunk = chunk;
			node->size = size;

			RB_INSERT(chunk_tree_s, &old_chunks, node);
		}
		malloc_mutex_unlock(&chunks_mtx);
	}

#ifdef USE_BRK
	if ((uintptr_t)chunk >= (uintptr_t)brk_base
	    && (uintptr_t)chunk < (uintptr_t)brk_max)
		madvise(chunk, size, MADV_FREE);
	else
#endif
		pages_unmap(chunk, size);

#ifdef MALLOC_STATS
	malloc_mutex_lock(&chunks_mtx);
	stats_chunks.curchunks -= (size / chunk_size);
	malloc_mutex_unlock(&chunks_mtx);
#endif
}

/*
 * End chunk management functions.
 */
/******************************************************************************/
/*
 * Begin arena.
 */

static inline int
arena_chunk_comp(arena_chunk_t *a, arena_chunk_t *b)
{

	assert(a != NULL);
	assert(b != NULL);

	if ((uintptr_t)a < (uintptr_t)b)
		return (-1);
	else if (a == b)
		return (0);
	else
		return (1);
}

/* Generate red-black tree code for arena chunks. */
RB_GENERATE_STATIC(arena_chunk_tree_s, arena_chunk_s, link, arena_chunk_comp);

static inline void
arena_run_mask_free_set(arena_run_t *run, unsigned reg)
{
	unsigned elm, bit;

	assert(run->magic == ARENA_RUN_MAGIC);
	assert(reg < run->bin->nregs);

	elm = reg / (sizeof(unsigned) << 3);
	if (elm < run->regs_minelm)
		run->regs_minelm = elm;
	bit = reg - (elm * (sizeof(unsigned) << 3));
	assert((run->regs_mask[elm] & (1 << bit)) == 0);
	run->regs_mask[elm] |= (1 << bit);
}

static inline void
arena_run_mask_free_unset(arena_run_t *run, unsigned reg)
{
	unsigned elm, bit;

	assert(run->magic == ARENA_RUN_MAGIC);
	assert(reg < run->bin->nregs);

	elm = reg / (sizeof(unsigned) << 3);
	bit = reg - (elm * (sizeof(unsigned) << 3));
	assert((run->regs_mask[elm] & (1 << bit)) != 0);
	run->regs_mask[elm] ^= (1 << bit);
}

static inline unsigned
arena_run_search(arena_run_t *run)
{
	unsigned i, mask, bit;

	assert(run->magic == ARENA_RUN_MAGIC);

	for (i = run->regs_minelm; i < REGS_MASK_NELMS; i++) {
		mask = run->regs_mask[i];
		if (mask != 0) {
			bit = ffs(mask);
			if (bit != 0) {
				/* Usable allocation found. */
				return ((i * (sizeof(unsigned) << 3))
				    + bit - 1);
			}
		} else {
			/* 
			 * Make a note that nothing before this element
			 * contains a free region.
			 */
			run->regs_minelm = i + 1;
		}
	}

	return (UINT_MAX);
}

static void
arena_run_split(arena_t *arena, arena_run_t *run, bool large, size_t size)
{
	arena_chunk_t *chunk;
	unsigned run_ind, map_offset, total_pages, need_pages;
	unsigned i, log2_run_pages, run_pages;

	chunk = (arena_chunk_t *)CHUNK_ADDR2BASE(run);
	run_ind = (unsigned)(((uintptr_t)run - (uintptr_t)chunk)
	    >> pagesize_2pow);
	assert(chunk->map[run_ind].free);
	total_pages = chunk->map[run_ind].npages;
	need_pages = (size >> pagesize_2pow);

#ifdef MALLOC_DEBUG
	for (i = 0; i < total_pages; i++) {
		assert(chunk->map[run_ind + i].free);
		assert(chunk->map[run_ind + i].large == false);
		assert(chunk->map[run_ind + i].npages == total_pages);
		assert(chunk->map[run_ind + i].pos == i);
	}
#endif

	/* Split enough pages from the front of run to fit allocation size. */
	map_offset = run_ind;
	for (i = 0; i < need_pages; i++) {
		chunk->map[map_offset + i].free = false;
		chunk->map[map_offset + i].large = large;
		chunk->map[map_offset + i].npages = need_pages;
		chunk->map[map_offset + i].pos = i;
	}

	/* Update map for trailing pages. */
	map_offset += need_pages;
	while (map_offset < run_ind + total_pages) {
		log2_run_pages = ffs(map_offset) - 1;
		run_pages = (1 << log2_run_pages);
		for (i = 0; i < run_pages; i++) {
			chunk->map[map_offset + i].free = true;
			chunk->map[map_offset + i].large = false;
			chunk->map[map_offset + i].npages = run_pages;
			chunk->map[map_offset + i].pos = i;
		}

		chunk->nfree_runs[log2_run_pages]++;

		map_offset += run_pages;
	}

	chunk->pages_used += (size >> pagesize_2pow);
}

static arena_chunk_t *
arena_chunk_alloc(arena_t *arena)
{
	arena_chunk_t *chunk;
	unsigned i, j, header_npages, pow2_header_npages, map_offset;
	unsigned log2_run_pages, run_pages;
	size_t header_size;

	chunk = (arena_chunk_t *)chunk_alloc(chunk_size);
	if (chunk == NULL)
		return (NULL);

	chunk->arena = arena;

	RB_INSERT(arena_chunk_tree_s, &arena->chunks, chunk);

	/*
	 * Claim that no pages are in use, since the header is merely overhead.
	 */
	chunk->pages_used = 0;

	memset(&chunk->nfree_runs, 0, sizeof(chunk->nfree_runs));

	header_size = (size_t)((uintptr_t)&chunk->map[arena_chunk_maplen]
	    - (uintptr_t)chunk);
	if (header_size % pagesize != 0) {
		/* Round up to the nearest page boundary. */
		header_size += pagesize - (header_size % pagesize);
	}

	header_npages = header_size / pagesize;
	pow2_header_npages = pow2_ceil(header_npages);

	/*
	 * Iteratively mark runs as in use, until we've spoken for the entire
	 * header.
	 */
	map_offset = 0;
	for (i = 0; header_npages > 0; i++) {
		if ((pow2_header_npages >> i) <= header_npages) {
			for (j = 0; j < (pow2_header_npages >> i); j++) {
				chunk->map[map_offset + j].free = false;
				chunk->map[map_offset + j].large = false;
				chunk->map[map_offset + j].npages =
				    (pow2_header_npages >> i);
				chunk->map[map_offset + j].pos = j;
			}
			header_npages -= (pow2_header_npages >> i);
			map_offset += (pow2_header_npages >> i);
		}
	}

	/*
	 * Finish initializing map.  The chunk header takes up some space at
	 * the beginning of the chunk, which we just took care of by
	 * "allocating" the leading pages.
	 */
	while (map_offset < (chunk_size / pagesize)) {
		log2_run_pages = ffs(map_offset) - 1;
		run_pages = (1 << log2_run_pages);
		for (i = 0; i < run_pages; i++) {
			chunk->map[map_offset + i].free = true;
			chunk->map[map_offset + i].large = false;
			chunk->map[map_offset + i].npages = run_pages;
			chunk->map[map_offset + i].pos = i;
		}

		chunk->nfree_runs[log2_run_pages]++;

		map_offset += run_pages;
	}

	return (chunk);
}

static void
arena_chunk_dealloc(arena_chunk_t *chunk)
{

	RB_REMOVE(arena_chunk_tree_s, &chunk->arena->chunks, chunk);

	chunk_dealloc((void *)chunk, chunk_size);
}

static void
arena_bin_run_refile(arena_t *arena, arena_bin_t *bin, arena_run_t *run,
    size_t size, bool promote)
{

	assert(bin == run->bin);

	/* Determine whether to promote or demote run. */
	if (promote) {
		/* Promote. */
		assert(run->free_min > run->nfree);
		assert(run->quartile < RUN_Q100);
		run->quartile++;
		if (run->quartile == RUN_Q75) {
			/*
			 * Skip RUN_Q75 during promotion from RUN_Q50.
			 * Separate handling of RUN_Q75 and RUN_Q100 allows
			 * us to keep completely full runs in RUN_Q100, thus
			 * guaranteeing that runs in RUN_Q75 are only mostly
			 * full.  This provides a method for avoiding a linear
			 * search for non-full runs, which avoids some
			 * pathological edge cases.
			 */
			run->quartile++;
		}
#ifdef MALLOC_STATS
		bin->stats.npromote++;
#endif
	} else {
		/* Demote. */
		assert(run->free_max < run->nfree);
		assert(run->quartile > RUN_QEMPTY);
		run->quartile--;
#ifdef MALLOC_STATS
		bin->stats.ndemote++;
#endif
	}

	/* Re-file run. */
	qr_remove(run, link);
	switch (run->quartile) {
		case RUN_QEMPTY:
#ifdef MALLOC_STATS
			bin->stats.curruns--;
#endif
			if (bin->runcur == run)
				bin->runcur = NULL;
#ifdef MALLOC_DEBUG
			run->magic = 0;
#endif
			arena_run_dalloc(arena, run, bin->run_size);
			break;
		case RUN_Q0:
			qr_before_insert(&bin->runs0, run, link);
			run->free_max = run->bin->nregs - 1;
			run->free_min = (run->bin->nregs >> 1) + 1;
			break;
		case RUN_Q25:
			qr_before_insert(&bin->runs25, run, link);
			run->free_max = ((run->bin->nregs >> 2) * 3) - 1;
			run->free_min = (run->bin->nregs >> 2) + 1;
			break;
		case RUN_Q50:
			qr_before_insert(&bin->runs50, run, link);
			run->free_max = (run->bin->nregs >> 1) - 1;
			run->free_min = 1;
			break;
		case RUN_Q75:
			qr_before_insert(&bin->runs75, run, link);
			run->free_max = (run->bin->nregs >> 2) - 1;
			run->free_min = 1;
			break;
		case RUN_Q100:
			assert(bin->runcur == run);
			bin->runcur = NULL;
			run->free_max = 0;
			run->free_min = 0;
			break;
		default:
			assert(0);
			break;
	}
}

static arena_run_t *
arena_run_alloc(arena_t *arena, bool large, size_t size)
{
	arena_run_t *run;
	unsigned min_ind, i, j;
	arena_chunk_t *chunk;
#ifndef NDEBUG
	int rep = 0;
#endif

	assert(size <= arena_maxclass);

AGAIN:
#ifndef NDEBUG
	rep++;
	assert(rep <= 2);
#endif

	min_ind = ffs(size / pagesize) - 1;
	RB_FOREACH(chunk, arena_chunk_tree_s, &arena->chunks) {
		for (i = min_ind;
		    i < (opt_chunk_2pow - pagesize_2pow);
		    i++) {
			if (chunk->nfree_runs[i] > 0) {
				arena_chunk_map_t *map = chunk->map;

				/* Scan chunk's map for free run. */
				for (j = 0; 
				    j < arena_chunk_maplen;
				    j += map[j].npages) {
					if (map[j].free
					    && map[j].npages == (1 << i))
		{
			run = (arena_run_t *)&((char *)chunk)[j
			    << pagesize_2pow];

			assert(chunk->nfree_runs[i] > 0);
			chunk->nfree_runs[i]--;

			/* Update page map. */
			arena_run_split(arena, run, large, size);

			return (run);
		}
				}
				/* Not reached. */
				assert(0);
			}
		}
	}

	/* No usable runs.  Allocate a new chunk, then try again. */
	if (arena_chunk_alloc(arena) == NULL)
		return (NULL);
	goto AGAIN;
}

static void
arena_run_dalloc(arena_t *arena, arena_run_t *run, size_t size)
{
	arena_chunk_t *chunk;
	unsigned i, run_ind, buddy_ind, base_run_ind, run_pages, log2_run_pages;

	chunk = (arena_chunk_t *)CHUNK_ADDR2BASE(run);
	run_ind = (unsigned)(((uintptr_t)run - (uintptr_t)chunk)
	    >> pagesize_2pow);
	run_pages = (size >> pagesize_2pow);
	log2_run_pages = ffs(run_pages) - 1;
	assert(run_pages > 0);

	/* Subtract pages from count of pages used in chunk. */
	chunk->pages_used -= run_pages;

	/* Mark run as deallocated. */
	for (i = 0; i < run_pages; i++) {
		chunk->map[run_ind + i].free = true;
		chunk->map[run_ind + i].large = false;
		chunk->map[run_ind + i].npages = run_pages;
		chunk->map[run_ind + i].pos = i;
	}

	/*
	 * Tell the kernel that we don't need the data in this run, but only
	 * if requested via runtime configuration.
	 */
	if (opt_hint) {
		madvise(run, size, MADV_FREE);
#ifdef MALLOC_STATS
		arena->stats.nmadvise += (size >> pagesize_2pow);
#endif
	}

	/*
	 * Iteratively coalesce with buddies.  Conceptually, the buddy scheme
	 * induces a tree on the set of pages.  If we know the number of pages
	 * in the subtree rooted at the current node, we can quickly determine
	 * whether a run is the left or right buddy, and then calculate the
	 * buddy's index.
	 */
	for (;
	    (run_pages = (1 << log2_run_pages)) < arena_chunk_maplen;
	    log2_run_pages++) {
		if (((run_ind >> log2_run_pages) & 1) == 0) {
			/* Current run precedes its buddy. */
			buddy_ind = run_ind + run_pages;
			base_run_ind = run_ind;
		} else {
			/* Current run follows its buddy. */
			buddy_ind = run_ind - run_pages;
			base_run_ind = buddy_ind;
		}

		if (chunk->map[buddy_ind].free == false
		    || chunk->map[buddy_ind].npages != run_pages)
			break;

		assert(chunk->nfree_runs[log2_run_pages] > 0);
		chunk->nfree_runs[log2_run_pages]--;

		/* Coalesce. */
		for (i = 0; i < (run_pages << 1); i++) {
			chunk->map[base_run_ind + i].npages = (run_pages << 1);
			chunk->map[base_run_ind + i].pos = i;
		}

		/* Update run_ind to be the begginning of the coalesced run. */
		run_ind = base_run_ind;
	}

	/* Insert coalesced run into ring of free runs. */
	chunk->nfree_runs[log2_run_pages]++;

	/* Free pages, to the extent possible. */
	if (chunk->pages_used == 0) {
		/* This chunk is completely unused now, so deallocate it. */
		arena_chunk_dealloc(chunk);
	}
}

static arena_run_t *
arena_bin_nonfull_run_get(arena_t *arena, arena_bin_t *bin, size_t size)
{
	arena_run_t *run;
	unsigned i, remainder;

	/* Look for a usable run. */
	if ((run = qr_next(&bin->runs50, link)) != &bin->runs50
	    || (run = qr_next(&bin->runs25, link)) != &bin->runs25
	    || (run = qr_next(&bin->runs0, link)) != &bin->runs0
	    || (run = qr_next(&bin->runs75, link)) != &bin->runs75) {
		/* run is guaranteed to have available space. */
		qr_remove(run, link);
		return (run);
	}

	/* Allocate a new run. */
	run = arena_run_alloc(arena, false, bin->run_size);
	if (run == NULL)
		return (NULL);

	/* Initialize run internals. */
	qr_new(run, link);
	run->bin = bin;

	for (i = 0; i < bin->nregs / (sizeof(unsigned) << 3); i++)
		run->regs_mask[i] = UINT_MAX;
	remainder = bin->nregs % (sizeof(unsigned) << 3);
	if (remainder != 0) {
		run->regs_mask[i] = (UINT_MAX >> ((sizeof(unsigned) << 3)
		    - remainder));
		i++;
	}
	for (; i < REGS_MASK_NELMS; i++)
		run->regs_mask[i] = 0;

	run->regs_minelm = 0;

	run->nfree = bin->nregs;
	run->quartile = RUN_QEMPTY;
	run->free_max = bin->nregs;
	run->free_min = ((bin->nregs >> 2) * 3) + 1;
#ifdef MALLOC_DEBUG
	run->magic = ARENA_RUN_MAGIC;
#endif

#ifdef MALLOC_STATS
	bin->stats.nruns++;
	bin->stats.curruns++;
	if (bin->stats.curruns > bin->stats.highruns)
		bin->stats.highruns = bin->stats.curruns;
#endif
	return (run);
}

static inline void *
arena_bin_malloc_easy(arena_t *arena, arena_bin_t *bin, arena_run_t *run,
    size_t size)
{
	void *ret;
	unsigned regind;

	assert(run->magic == ARENA_RUN_MAGIC);
	assert(run->nfree > 0);

	regind = arena_run_search(run);
	assert(regind != UINT_MAX);
	assert(regind < bin->nregs);

	ret = (void *)&((char *)run)[bin->reg0_offset + (bin->reg_size
	    * regind)];
	arena_run_mask_free_unset(run, regind);
	run->nfree--;
	if (run->nfree < run->free_min) {
		/* Promote run to higher fullness quartile. */
		arena_bin_run_refile(arena, bin, run, size, true);
	}

	return (ret);
}

static void *
arena_bin_malloc_hard(arena_t *arena, arena_bin_t *bin, size_t size)
{

	assert(bin->runcur == NULL || bin->runcur->quartile == RUN_Q100);

	bin->runcur = arena_bin_nonfull_run_get(arena, bin, size);
	if (bin->runcur == NULL)
		return (NULL);
	assert(bin->runcur->magic == ARENA_RUN_MAGIC);

	return (arena_bin_malloc_easy(arena, bin, bin->runcur, size));
}

static void *
arena_malloc(arena_t *arena, size_t size)
{
	void *ret;

	assert(arena != NULL);
	assert(arena->magic == ARENA_MAGIC);
	assert(size != 0);
	assert(QUANTUM_CEILING(size) <= arena_maxclass);

	malloc_mutex_lock(&arena->mtx);
	if (size <= bin_maxclass) {
		arena_bin_t *bin;
		arena_run_t *run;

		if (size < small_min) {
			size = pow2_ceil(size);
			bin = &arena->bins[ffs(size >> (TINY_MIN_2POW + 1))];
#ifdef MALLOC_STATS
			/* 
			 * Bin calculation is always correct, but we may need to
			 * fix size for the purposes of stats accuracy.
			 */
			if (size < (1 << TINY_MIN_2POW))
				size = (1 << TINY_MIN_2POW);
#endif
		} else if (size <= small_max) {
			size = QUANTUM_CEILING(size);
			bin = &arena->bins[ntbins + (size >> opt_quantum_2pow)
			    - 1];
		} else {
			size = pow2_ceil(size);
			bin = &arena->bins[ntbins + nqbins
			    + (ffs(size >> opt_small_max_2pow) - 2)];
		}
		assert(size == bin->reg_size);

		if ((run = bin->runcur) != NULL)
			ret = arena_bin_malloc_easy(arena, bin, run, size);
		else
			ret = arena_bin_malloc_hard(arena, bin, size);

#ifdef MALLOC_STATS
		bin->stats.nrequests++;
#endif
	} else {
		size = pow2_ceil(size);
		ret = (void *)arena_run_alloc(arena, true, size);
	}

#ifdef MALLOC_STATS
	if (ret != NULL)
		arena->allocated += size;
#endif

	malloc_mutex_unlock(&arena->mtx);

	if (opt_junk && ret != NULL)
		memset(ret, 0xa5, size);
	else if (opt_zero && ret != NULL)
		memset(ret, 0, size);
	return (ret);
}

static void *
arena_ralloc(arena_t *arena, void *ptr, size_t size, size_t oldsize)
{
	void *ret;

	/*
	 * Avoid moving the allocation if the size class would not
	 * change.
	 */
	if (size < small_min) {
		if (oldsize < small_min &&
		    ffs(pow2_ceil(size) >> (TINY_MIN_2POW + 1))
		    == ffs(pow2_ceil(oldsize) >> (TINY_MIN_2POW + 1)))
			goto IN_PLACE;
	} else if (size <= small_max) {
		if (oldsize >= small_min && oldsize <= small_max && 
		    (QUANTUM_CEILING(size) >> opt_quantum_2pow)
		    == (QUANTUM_CEILING(oldsize) >> opt_quantum_2pow))
			goto IN_PLACE;
	} else {
		if (oldsize > small_max &&
		    pow2_ceil(size) == pow2_ceil(oldsize))
			goto IN_PLACE;
	}

	/*
	 * If we get here, then size and oldsize are different enough
	 * that we need to use a different size class.  In that case,
	 * fall back to allocating new space and copying.
	 */
	ret = arena_malloc(arena, size);
	if (ret == NULL)
		return (NULL);

	if (size < oldsize)
		memcpy(ret, ptr, size);
	else
		memcpy(ret, ptr, oldsize);
	idalloc(ptr);
	return (ret);
IN_PLACE:
	if (opt_junk && size < oldsize)
		memset(&((char *)ptr)[size], 0x5a, oldsize - size);
	else if (opt_zero && size > oldsize)
		memset(&((char *)ptr)[size], 0, size - oldsize);
	return (ptr);
}

static size_t
arena_salloc(arena_t *arena, void *ptr)
{
	size_t ret;
	arena_chunk_t *chunk;
	uint32_t pageind;
	arena_chunk_map_t *mapelm;

	assert(arena != NULL);
	assert(arena->magic == ARENA_MAGIC);
	assert(ptr != NULL);
	assert(ptr != &nil);
	assert(CHUNK_ADDR2BASE(ptr) != ptr);

	malloc_mutex_lock(&arena->mtx);
	chunk = (arena_chunk_t *)CHUNK_ADDR2BASE(ptr);
	pageind = (((uintptr_t)ptr - (uintptr_t)chunk) >> pagesize_2pow);
	mapelm = &chunk->map[pageind];
	assert(mapelm->free == false);
	if (mapelm->large == false) {
		arena_run_t *run;

		pageind -= mapelm->pos;
		mapelm = &chunk->map[pageind];
		
		run = (arena_run_t *)&((char *)chunk)[pageind << pagesize_2pow];
		assert(run->magic == ARENA_RUN_MAGIC);
		ret = run->bin->reg_size;
	} else
		ret = mapelm->npages << pagesize_2pow;
		
	malloc_mutex_unlock(&arena->mtx);

	return (ret);
}

static void
arena_dalloc(arena_t *arena, void *ptr)
{
	arena_chunk_t *chunk;
	unsigned pageind;
	arena_chunk_map_t *mapelm;
	size_t size;

	assert(arena != NULL);
	assert(arena->magic == ARENA_MAGIC);
	assert(ptr != NULL);
	assert(ptr != &nil);
	assert(CHUNK_ADDR2BASE(ptr) != ptr);

	malloc_mutex_lock(&arena->mtx);

	chunk = (arena_chunk_t *)CHUNK_ADDR2BASE(ptr);
	pageind = (((uintptr_t)ptr - (uintptr_t)chunk) >> pagesize_2pow);
	mapelm = &chunk->map[pageind];
	assert(mapelm->free == false);
	if (mapelm->large == false) {
		arena_run_t *run;
		unsigned regind;

		pageind -= mapelm->pos;
		mapelm = &chunk->map[pageind];

		run = (arena_run_t *)&((char *)chunk)[pageind << pagesize_2pow];
		assert(run->magic == ARENA_RUN_MAGIC);
		size = run->bin->reg_size;

		if (opt_junk)
			memset(ptr, 0x5a, size);

		regind = (unsigned)(((uintptr_t)ptr
		    - (uintptr_t)&((char *)run)[run->bin->reg0_offset])
		    / run->bin->reg_size);
		arena_run_mask_free_set(run, regind);
		run->nfree++;
		if (run->nfree > run->free_max) {
			/* Demote run to lower fullness quartile. */
			arena_bin_run_refile(arena, run->bin, run, size, false);
		}
	} else {
		size = mapelm->npages << pagesize_2pow;

		if (opt_junk)
			memset(ptr, 0x5a, size);

		arena_run_dalloc(arena, (arena_run_t *)ptr, size);
	}

#ifdef MALLOC_STATS
	arena->allocated -= size;
#endif

	malloc_mutex_unlock(&arena->mtx);
}

#ifdef MALLOC_STATS
static size_t
arena_allocated(arena_t *arena)
{
	size_t ret;

	assert(arena != NULL);
	assert(arena->magic == ARENA_MAGIC);

	malloc_mutex_lock(&arena->mtx);
	ret = arena->allocated;
	malloc_mutex_unlock(&arena->mtx);

	return (ret);
}
#endif

static bool
arena_new(arena_t *arena)
{
	unsigned i;
	arena_bin_t *bin;
	size_t pow2_size, run_size;

	malloc_mutex_init(&arena->mtx);

#ifdef MALLOC_STATS
	arena->allocated = 0;

	memset(&arena->stats, 0, sizeof(arena_stats_t));
#endif

	/* Initialize chunks. */
	RB_INIT(&arena->chunks);

	/* Initialize bins. */

	/* (2^n)-spaced tiny bins. */
	for (i = 0; i < ntbins; i++) {
		bin = &arena->bins[i];
		bin->runcur = NULL;
		qr_new(&bin->runs0, link);
		qr_new(&bin->runs25, link);
		qr_new(&bin->runs50, link);
		qr_new(&bin->runs75, link);

		bin->reg_size = (1 << (TINY_MIN_2POW + i));

		/* 
		 * Calculate how large of a run to allocate.  Make sure that at
		 * least RUN_MIN_REGS regions fit in the run.
		 */
		run_size = bin->reg_size << RUN_MIN_REGS_2POW;
		if (run_size < pagesize)
			run_size = pagesize;
		if (run_size > (pagesize << RUN_MAX_PAGES_2POW))
			run_size = (pagesize << RUN_MAX_PAGES_2POW);
		if (run_size > arena_maxclass)
			run_size = arena_maxclass;
		bin->run_size = run_size;

		assert(run_size >= sizeof(arena_run_t));
		bin->nregs = (run_size - sizeof(arena_run_t)) / bin->reg_size;
		if (bin->nregs > REGS_MASK_NELMS * (sizeof(unsigned) << 3)) {
			/* Take care not to overflow regs_mask. */
			bin->nregs = REGS_MASK_NELMS * (sizeof(unsigned) << 3);
		}
		bin->reg0_offset = run_size - (bin->nregs * bin->reg_size);

#ifdef MALLOC_STATS
		memset(&bin->stats, 0, sizeof(malloc_bin_stats_t));
#endif
	}

	/* Quantum-spaced bins. */
	for (; i < ntbins + nqbins; i++) {
		bin = &arena->bins[i];
		bin->runcur = NULL;
		qr_new(&bin->runs0, link);
		qr_new(&bin->runs25, link);
		qr_new(&bin->runs50, link);
		qr_new(&bin->runs75, link);

		bin->reg_size = quantum * (i - ntbins + 1);

		/* 
		 * Calculate how large of a run to allocate.  Make sure that at
		 * least RUN_MIN_REGS regions fit in the run.
		 */
		pow2_size = pow2_ceil(quantum * (i - ntbins + 1));
		run_size = (pow2_size << RUN_MIN_REGS_2POW);
		if (run_size < pagesize)
			run_size = pagesize;
		if (run_size > (pagesize << RUN_MAX_PAGES_2POW))
			run_size = (pagesize << RUN_MAX_PAGES_2POW);
		if (run_size > arena_maxclass)
			run_size = arena_maxclass;
		bin->run_size = run_size;

		bin->nregs = (run_size - sizeof(arena_run_t)) / bin->reg_size;
		assert(bin->nregs <= REGS_MASK_NELMS * (sizeof(unsigned) << 3));
		bin->reg0_offset = run_size - (bin->nregs * bin->reg_size);

#ifdef MALLOC_STATS
		memset(&bin->stats, 0, sizeof(malloc_bin_stats_t));
#endif
	}

	/* (2^n)-spaced bins. */
	for (; i < ntbins + nqbins + npbins; i++) {
		bin = &arena->bins[i];
		bin->runcur = NULL;
		qr_new(&bin->runs0, link);
		qr_new(&bin->runs25, link);
		qr_new(&bin->runs50, link);
		qr_new(&bin->runs75, link);

		bin->reg_size = (small_max << (i - (ntbins + nqbins) + 1));

		/* 
		 * Calculate how large of a run to allocate.  Make sure that at
		 * least RUN_MIN_REGS regions fit in the run.
		 */
		run_size = bin->reg_size << RUN_MIN_REGS_2POW;
		if (run_size < pagesize)
			run_size = pagesize;
		if (run_size > (pagesize << RUN_MAX_PAGES_2POW))
			run_size = (pagesize << RUN_MAX_PAGES_2POW);
		if (run_size > arena_maxclass)
			run_size = arena_maxclass;
		bin->run_size = run_size;

		bin->nregs = (run_size - sizeof(arena_run_t)) / bin->reg_size;
		assert(bin->nregs <= REGS_MASK_NELMS * (sizeof(unsigned) << 3));
		bin->reg0_offset = run_size - (bin->nregs * bin->reg_size);

#ifdef MALLOC_STATS
		memset(&bin->stats, 0, sizeof(malloc_bin_stats_t));
#endif
	}

#ifdef MALLOC_DEBUG
	arena->magic = ARENA_MAGIC;
#endif

	return (false);
}

/* Create a new arena and insert it into the arenas array at index ind. */
static arena_t *
arenas_extend(unsigned ind)
{
	arena_t *ret;

	/* Allocate enough space for trailing bins. */
	ret = (arena_t *)base_alloc(sizeof(arena_t)
	    + (sizeof(arena_bin_t) * (ntbins + nqbins + npbins - 1)));
	if (ret != NULL && arena_new(ret) == false) {
		arenas[ind] = ret;
		return (ret);
	}
	/* Only reached if there is an OOM error. */

	/*
	 * OOM here is quite inconvenient to propagate, since dealing with it
	 * would require a check for failure in the fast path.  Instead, punt
	 * by using arenas[0].  In practice, this is an extremely unlikely
	 * failure.
	 */
	malloc_printf("%s: (malloc) Error initializing arena\n",
	    _getprogname());
	if (opt_abort)
		abort();

	return (arenas[0]);
}

/*
 * End arena.
 */
/******************************************************************************/
/*
 * Begin general internal functions.
 */

/*
 * Choose an arena based on a per-thread value (fast-path code, calls slow-path
 * code if necessary.
 */
static inline arena_t *
choose_arena(void)
{
	arena_t *ret;

	/*
	 * We can only use TLS if this is a PIC library, since for the static
	 * library version, libc's malloc is used by TLS allocation, which
	 * introduces a bootstrapping issue.
	 */
#ifndef NO_TLS
	ret = arenas_map;
	if (ret == NULL)
		ret = choose_arena_hard();
#else
	if (__isthreaded) {
		unsigned long ind;
		
		/*
		 * Hash _pthread_self() to one of the arenas.  There is a prime
		 * number of arenas, so this has a reasonable chance of
		 * working.  Even so, the hashing can be easily thwarted by
		 * inconvenient _pthread_self() values.  Without specific
		 * knowledge of how _pthread_self() calculates values, we can't
		 * do much better than this.
		 */
		ind = (unsigned long) _pthread_self() % narenas;

		/*
		 * Optimistially assume that arenas[ind] has been initialized.
		 * At worst, we find out that some other thread has already
		 * done so, after acquiring the lock in preparation.  Note that
		 * this lazy locking also has the effect of lazily forcing
		 * cache coherency; without the lock acquisition, there's no
		 * guarantee that modification of arenas[ind] by another thread
		 * would be seen on this CPU for an arbitrary amount of time.
		 *
		 * In general, this approach to modifying a synchronized value
		 * isn't a good idea, but in this case we only ever modify the
		 * value once, so things work out well.
		 */
		ret = arenas[ind];
		if (ret == NULL) {
			/*
			 * Avoid races with another thread that may have already
			 * initialized arenas[ind].
			 */
			malloc_mutex_lock(&arenas_mtx);
			if (arenas[ind] == NULL)
				ret = arenas_extend((unsigned)ind);
			else
				ret = arenas[ind];
			malloc_mutex_unlock(&arenas_mtx);
		}
	} else
		ret = arenas[0];
#endif

	return (ret);
}

#ifndef NO_TLS
/*
 * Choose an arena based on a per-thread value (slow-path code only, called
 * only by choose_arena()).
 */
static arena_t *
choose_arena_hard(void)
{
	arena_t *ret;

	/* Assign one of the arenas to this thread, in a round-robin fashion. */
	if (__isthreaded) {
		malloc_mutex_lock(&arenas_mtx);
		ret = arenas[next_arena];
		if (ret == NULL)
			ret = arenas_extend(next_arena);
		next_arena = (next_arena + 1) % narenas;
		malloc_mutex_unlock(&arenas_mtx);
	} else
		ret = arenas[0];
	arenas_map = ret;

	return (ret);
}
#endif

static void *
huge_malloc(size_t size)
{
	void *ret;
	size_t chunk_size;
	chunk_node_t *node;

	/* Allocate a chunk for this request. */

	chunk_size = CHUNK_CEILING(size);
	if (chunk_size == 0) {
		/* size is large enough to cause size_t wrap-around. */
		return (NULL);
	}

	/* Allocate a chunk node with which to track the chunk. */
	node = base_chunk_node_alloc();
	if (node == NULL)
		return (NULL);

	ret = chunk_alloc(chunk_size);
	if (ret == NULL) {
		base_chunk_node_dealloc(node);
		return (NULL);
	}

	/* Insert node into chunks. */
	node->chunk = ret;
	node->size = chunk_size;

	malloc_mutex_lock(&chunks_mtx);
	RB_INSERT(chunk_tree_s, &huge, node);
#ifdef MALLOC_STATS
	huge_nmalloc++;
	huge_allocated += chunk_size;
#endif
	malloc_mutex_unlock(&chunks_mtx);

	if (opt_junk && ret != NULL)
		memset(ret, 0xa5, chunk_size);
	else if (opt_zero && ret != NULL)
		memset(ret, 0, chunk_size);

	return (ret);
}

static void *
huge_ralloc(void *ptr, size_t size, size_t oldsize)
{
	void *ret;

	/*
	 * Avoid moving the allocation if the size class would not
	 * change.
	 */
	if (oldsize > arena_maxclass &&
	    CHUNK_CEILING(size) == CHUNK_CEILING(oldsize)) {
		if (opt_junk && size < oldsize)
			memset(&((char *)ptr)[size], 0x5a, oldsize - size);
		else if (opt_zero && size > oldsize)
			memset(&((char *)ptr)[size], 0, size - oldsize);
		return (ptr);
	}

	/*
	 * If we get here, then size and oldsize are different enough
	 * that we need to use a different size class.  In that case,
	 * fall back to allocating new space and copying.
	 */
	ret = huge_malloc(size);
	if (ret == NULL)
		return (NULL);

	if (CHUNK_ADDR2BASE(ptr) == ptr) {
		/* The old allocation is a chunk. */
		if (size < oldsize)
			memcpy(ret, ptr, size);
		else
			memcpy(ret, ptr, oldsize);
	} else {
		/* The old allocation is a region. */
		assert(oldsize < size);
		memcpy(ret, ptr, oldsize);
	}
	idalloc(ptr);
	return (ret);
}

static void
huge_dalloc(void *ptr)
{
	chunk_node_t key;
	chunk_node_t *node;

	malloc_mutex_lock(&chunks_mtx);

	/* Extract from tree of huge allocations. */
	key.chunk = ptr;
	node = RB_FIND(chunk_tree_s, &huge, &key);
	assert(node != NULL);
	assert(node->chunk == ptr);
	RB_REMOVE(chunk_tree_s, &huge, node);

#ifdef MALLOC_STATS
	/* Update counters. */
	huge_ndalloc++;
	huge_allocated -= node->size;
#endif

	malloc_mutex_unlock(&chunks_mtx);

	/* Unmap chunk. */
#ifdef USE_BRK
	if (opt_junk)
		memset(node->chunk, 0x5a, node->size);
#endif
	chunk_dealloc(node->chunk, node->size);

	base_chunk_node_dealloc(node);
}

static void *
imalloc(arena_t *arena, size_t size)
{
	void *ret;

	assert(arena != NULL);
	assert(arena->magic == ARENA_MAGIC);
	assert(size != 0);

	if (size <= arena_maxclass)
		ret = arena_malloc(arena, size);
	else
		ret = huge_malloc(size);

#ifdef MALLOC_STATS
	malloc_mutex_lock(&arena->mtx);
	arena->stats.nmalloc++;
	malloc_mutex_unlock(&arena->mtx);
#endif

	return (ret);
}

static void *
ipalloc(arena_t *arena, size_t alignment, size_t size)
{
	void *ret;
	size_t pow2_size;

	assert(arena != NULL);
	assert(arena->magic == ARENA_MAGIC);

	/* 
	 * Round up to the nearest power of two that is >= alignment and
	 * >= size. 
	 */
	if (size > alignment)
		pow2_size = pow2_ceil(size);
	else
		pow2_size = alignment;
	pow2_size = QUANTUM_CEILING(pow2_size);
	if (pow2_size < size) {
		/* size_t overflow. */
		return (NULL);
	}

	if (pow2_size <= arena_maxclass)
		ret = arena_malloc(arena, pow2_size);
	else {
		if (alignment <= chunk_size)
			ret = huge_malloc(size);
		else {
			size_t chunksize, alloc_size, offset;
			chunk_node_t *node;

			/*
			 * This allocation requires alignment that is even
			 * larger than chunk alignment.  This means that
			 * huge_malloc() isn't good enough.
			 *
			 * Allocate almost twice as many chunks as are demanded
			 * by the size or alignment, in order to assure the
			 * alignment can be achieved, then unmap leading and
			 * trailing chunks.
			 */

			chunksize = CHUNK_CEILING(size);

			if (size >= alignment)
				alloc_size = chunksize + alignment - chunk_size;
			else
				alloc_size = (alignment << 1) - chunk_size;

			/*
			 * Allocate a chunk node with which to track the chunk.
			 */
			node = base_chunk_node_alloc();
			if (node == NULL)
				return (NULL);

			ret = chunk_alloc(alloc_size);
			if (ret == NULL) {
				base_chunk_node_dealloc(node);
				return (NULL);
			}

			offset = (uintptr_t)ret & (alignment - 1);
			assert(offset % chunk_size == 0);
			assert(offset < alloc_size);
			if (offset == 0) {
				/* Trim trailing space. */
				chunk_dealloc((void *)((uintptr_t)ret
				    + chunksize), alloc_size - chunksize);
			} else {
				size_t trailsize;

				/* Trim leading space. */
				chunk_dealloc(ret, alignment - offset);

				ret = (void *)((uintptr_t)ret + (alignment
				    - offset));

				trailsize = alloc_size - (alignment - offset)
				    - chunksize;
				if (trailsize != 0) {
				    /* Trim trailing space. */
				    assert(trailsize < alloc_size);
				    chunk_dealloc((void *)((uintptr_t)ret
				        + chunksize), trailsize);
				}
			}

			/* Insert node into chunks. */
			node->chunk = ret;
			node->size = chunksize;

			malloc_mutex_lock(&chunks_mtx);
			RB_INSERT(chunk_tree_s, &huge, node);
#ifdef MALLOC_STATS
			huge_allocated += size;
#endif
			malloc_mutex_unlock(&chunks_mtx);

			if (opt_junk)
				memset(ret, 0xa5, chunksize);
			else if (opt_zero)
				memset(ret, 0, chunksize);
		}
	}

#ifdef MALLOC_STATS
	malloc_mutex_lock(&arena->mtx);
	arena->stats.npalloc++;
	malloc_mutex_unlock(&arena->mtx);
#endif
	assert(((uintptr_t)ret & (alignment - 1)) == 0);
	return (ret);
}

static void *
icalloc(arena_t *arena, size_t size)
{
	void *ret;

	assert(arena != NULL);
	assert(arena->magic == ARENA_MAGIC);

	if (size <= arena_maxclass) {
		ret = arena_malloc(arena, size);
		if (ret == NULL)
			return (NULL);
		memset(ret, 0, size);
	} else {
		/*
		 * The virtual memory system provides zero-filled pages, so
		 * there is no need to do so manually, unless opt_junk is
		 * enabled, in which case huge_malloc() fills huge allocations
		 * with junk.
		 */
		ret = huge_malloc(size);
		if (ret == NULL)
			return (NULL);

		if (opt_junk)
			memset(ret, 0, size);
#ifdef USE_BRK
		else if ((uintptr_t)ret >= (uintptr_t)brk_base
		    && (uintptr_t)ret < (uintptr_t)brk_max) {
			/* 
			 * This may be a re-used brk chunk.  Therefore, zero
			 * the memory.
			 */
			memset(ret, 0, size);
		}
#endif
	}

#ifdef MALLOC_STATS
	malloc_mutex_lock(&arena->mtx);
	arena->stats.ncalloc++;
	malloc_mutex_unlock(&arena->mtx);
#endif

	return (ret);
}

static void *
iralloc(arena_t *arena, void *ptr, size_t size)
{
	void *ret;
	size_t oldsize;

	assert(arena != NULL);
	assert(arena->magic == ARENA_MAGIC);
	assert(ptr != NULL);
	assert(ptr != &nil);
	assert(size != 0);

	oldsize = isalloc(ptr);

	if (size <= arena_maxclass)
		ret = arena_ralloc(arena, ptr, size, oldsize);
	else
		ret = huge_ralloc(ptr, size, oldsize);

#ifdef MALLOC_STATS
	malloc_mutex_lock(&arena->mtx);
	arena->stats.nralloc++;
	malloc_mutex_unlock(&arena->mtx);
#endif
	return (ret);
}

static size_t
isalloc(void *ptr)
{
	size_t ret;
	arena_chunk_t *chunk;

	assert(ptr != NULL);
	assert(ptr != &nil);

	chunk = (arena_chunk_t *)CHUNK_ADDR2BASE(ptr);
	if (chunk != ptr) {
		/* Region. */
		assert(chunk->arena->magic == ARENA_MAGIC);

		ret = arena_salloc(chunk->arena, ptr);
	} else {
		chunk_node_t *node, key;

		/* Chunk (huge allocation). */

		malloc_mutex_lock(&chunks_mtx);

		/* Extract from tree of huge allocations. */
		key.chunk = ptr;
		node = RB_FIND(chunk_tree_s, &huge, &key);
		assert(node != NULL);

		ret = node->size;

		malloc_mutex_unlock(&chunks_mtx);
	}

	return (ret);
}

static void
idalloc(void *ptr)
{
	arena_chunk_t *chunk;

	assert(ptr != NULL);
	assert(ptr != &nil);

	chunk = (arena_chunk_t *)CHUNK_ADDR2BASE(ptr);
	if (chunk != ptr) {
		/* Region. */
#ifdef MALLOC_STATS
		malloc_mutex_lock(&chunk->arena->mtx);
		chunk->arena->stats.ndalloc++;
		malloc_mutex_unlock(&chunk->arena->mtx);
#endif
		arena_dalloc(chunk->arena, ptr);
	} else
		huge_dalloc(ptr);
}

#ifdef MALLOC_STATS
static void
istats(size_t *allocated, size_t *total)
{
	size_t tallocated, ttotal;
	unsigned i;

	tallocated = 0;

	/* arenas. */
	for (i = 0; i < narenas; i++) {
		if (arenas[i] != NULL)
			tallocated += arena_allocated(arenas[i]);
	}

	/* huge. */
	malloc_mutex_lock(&chunks_mtx);
	tallocated += huge_allocated;
	ttotal = stats_chunks.curchunks * chunk_size;
	malloc_mutex_unlock(&chunks_mtx);

	/* Return results. */
	*allocated = tallocated;
	*total = ttotal;
}
#endif

static void
malloc_print_stats(void)
{

	if (opt_print_stats) {
		malloc_printf("___ Begin malloc statistics ___\n");
		malloc_printf("Number of CPUs: %u\n", ncpus);
		malloc_printf("Number of arenas: %u\n", narenas);
		malloc_printf("Chunk size: %zu (2^%zu)\n", chunk_size,
		    opt_chunk_2pow);
		malloc_printf("Quantum size: %zu (2^%zu)\n", quantum, 
		    opt_quantum_2pow);
		malloc_printf("Max small size: %zu\n", small_max);
		malloc_printf("Pointer size: %u\n", sizeof(void *));
		malloc_printf("Assertions %s\n",
#ifdef NDEBUG
		    "disabled"
#else
		    "enabled"
#endif
		    );

#ifdef MALLOC_STATS
		{
			size_t a, b;

			istats(&a, &b);
			malloc_printf("Allocated: %zu, space used: %zu\n", a,
			    b);
		}

		{
			arena_t *arena;
			unsigned i;

			/* Print chunk stats. */
			{
				chunk_stats_t chunks_stats;

				malloc_mutex_lock(&chunks_mtx);
				chunks_stats = stats_chunks;
				malloc_mutex_unlock(&chunks_mtx);

				malloc_printf("\nchunks:\n");
				malloc_printf(" %13s%13s%13s\n", "nchunks",
				    "highchunks", "curchunks");
				malloc_printf(" %13llu%13lu%13lu\n",
				    chunks_stats.nchunks, 
				    chunks_stats.highchunks,
				    chunks_stats.curchunks);
			}

			/* Print chunk stats. */
			malloc_printf("\nhuge:\n");
			malloc_printf("%12s %12s %12s\n",
			    "nmalloc", "ndalloc", "allocated");
			malloc_printf("%12llu %12llu %12zu\n",
			    huge_nmalloc, huge_ndalloc, huge_allocated);

			/* Print stats for each arena. */
			for (i = 0; i < narenas; i++) {
				arena = arenas[i];
				if (arena != NULL) {
					malloc_printf(
					    "\narenas[%u] statistics:\n", i);
					malloc_mutex_lock(&arena->mtx);
					stats_print(arena);
					malloc_mutex_unlock(&arena->mtx);
				} else {
					malloc_printf("\narenas[%u] statistics:"
					    " unused arena\n", i);
				}
			}
		}
#endif /* #ifdef MALLOC_STATS */
		malloc_printf("--- End malloc statistics ---\n");
	}
}

/*
 * FreeBSD's pthreads implementation calls malloc(3), so the malloc
 * implementation has to take pains to avoid infinite recursion during
 * initialization.
 *
 * atomic_init_start() returns true if it started initializing.  In that case,
 * the caller must also call atomic_init_finish(), just before returning
 * to its caller.  This delayed finalization of initialization is critical,
 * since otherwise choose_arena() has no way to know whether it's safe
 * to call _pthread_self().
 */
static inline bool
malloc_init(void)
{

	/*
	 * We always initialize before threads are created, since any thread
	 * creation first triggers allocations.
	 */
	assert(__isthreaded == 0 || malloc_initialized);

	if (malloc_initialized == false)
		return (malloc_init_hard());

	return (false);
}

static bool
malloc_init_hard(void)
{
	unsigned i, j;
	int linklen;
	char buf[PATH_MAX + 1];
	const char *opts;

	/* Get number of CPUs. */
	{
		int mib[2];
		size_t len;

		mib[0] = CTL_HW;
		mib[1] = HW_NCPU;
		len = sizeof(ncpus);
		if (sysctl(mib, 2, &ncpus, &len, (void *) 0, 0) == -1) {
			/* Error. */
			ncpus = 1;
		}
	}

	/* Get page size. */
	{
		long result;

		result = sysconf(_SC_PAGESIZE);
		assert(result != -1);
		pagesize = (unsigned) result;

		/*
		 * We assume that pagesize is a power of 2 when calculating
		 * pagesize_2pow.
		 */
		assert(((result - 1) & result) == 0);
		pagesize_2pow = ffs(result) - 1;
	}

	for (i = 0; i < 3; i++) {
		/* Get runtime configuration. */
		switch (i) {
		case 0:
			if ((linklen = readlink("/etc/malloc.conf", buf,
						sizeof(buf) - 1)) != -1) {
				/*
				 * Use the contents of the "/etc/malloc.conf"
				 * symbolic link's name.
				 */
				buf[linklen] = '\0';
				opts = buf;
			} else {
				/* No configuration specified. */
				buf[0] = '\0';
				opts = buf;
			}
			break;
		case 1:
			if (issetugid() == 0 && (opts =
			    getenv("MALLOC_OPTIONS")) != NULL) {
				/*
				 * Do nothing; opts is already initialized to
				 * the value of the MALLOC_OPTIONS environment
				 * variable.
				 */
			} else {
				/* No configuration specified. */
				buf[0] = '\0';
				opts = buf;
			}
			break;
		case 2:
			if (_malloc_options != NULL) {
			    /*
			     * Use options that were compiled into the program.
			     */
			    opts = _malloc_options;
			} else {
				/* No configuration specified. */
				buf[0] = '\0';
				opts = buf;
			}
			break;
		default:
			/* NOTREACHED */
			assert(false);
		}

		for (j = 0; opts[j] != '\0'; j++) {
			switch (opts[j]) {
			case 'a':
				opt_abort = false;
				break;
			case 'A':
				opt_abort = true;
				break;
			case 'h':
				opt_hint = false;
				break;
			case 'H':
				opt_hint = true;
				break;
			case 'j':
				opt_junk = false;
				break;
			case 'J':
				opt_junk = true;
				break;
			case 'k':
				/*
				 * Run fullness quartile limits don't have
				 * enough resolution if there are too few
				 * regions for the largest bin size classes.
				 */
				if (opt_chunk_2pow > pagesize_2pow + 3)
					opt_chunk_2pow--;
				break;
			case 'K':
				if (opt_chunk_2pow < CHUNK_2POW_MAX)
					opt_chunk_2pow++;
				break;
			case 'n':
				opt_narenas_lshift--;
				break;
			case 'N':
				opt_narenas_lshift++;
				break;
			case 'p':
				opt_print_stats = false;
				break;
			case 'P':
				opt_print_stats = true;
				break;
			case 'q':
				if (opt_quantum_2pow > QUANTUM_2POW_MIN)
					opt_quantum_2pow--;
				break;
			case 'Q':
				if (opt_quantum_2pow < pagesize_2pow - 1)
					opt_quantum_2pow++;
				break;
			case 's':
				if (opt_small_max_2pow > QUANTUM_2POW_MIN)
					opt_small_max_2pow--;
				break;
			case 'S':
				if (opt_small_max_2pow < pagesize_2pow - 1)
					opt_small_max_2pow++;
				break;
			case 'u':
				opt_utrace = false;
				break;
			case 'U':
				opt_utrace = true;
				break;
			case 'v':
				opt_sysv = false;
				break;
			case 'V':
				opt_sysv = true;
				break;
			case 'x':
				opt_xmalloc = false;
				break;
			case 'X':
				opt_xmalloc = true;
				break;
			case 'z':
				opt_zero = false;
				break;
			case 'Z':
				opt_zero = true;
				break;
			default:
				malloc_printf("%s: (malloc) Unsupported"
				    " character in malloc options: '%c'\n",
				    _getprogname(), opts[j]);
			}
		}
	}

	/* Take care to call atexit() only once. */
	if (opt_print_stats) {
		/* Print statistics at exit. */
		atexit(malloc_print_stats);
	}

	/* Set variables according to the value of opt_small_max_2pow. */
	if (opt_small_max_2pow < opt_quantum_2pow)
		opt_small_max_2pow = opt_quantum_2pow;
	small_max = (1 << opt_small_max_2pow);

	/* Set bin-related variables. */
	bin_maxclass = (pagesize >> 1);
	ntbins = opt_quantum_2pow - TINY_MIN_2POW;
	assert(ntbins <= opt_quantum_2pow);
	nqbins = (small_max >> opt_quantum_2pow);
	npbins = pagesize_2pow - opt_small_max_2pow - 1;

	/* Set variables according to the value of opt_quantum_2pow. */
	quantum = (1 << opt_quantum_2pow);
	quantum_mask = quantum - 1;
	small_min = (quantum >> 1) + 1;
	assert(small_min <= quantum);

	/* Set variables according to the value of opt_chunk_2pow. */
	chunk_size = (1 << opt_chunk_2pow);
	chunk_size_mask = chunk_size - 1;
	arena_chunk_maplen = (1 << (opt_chunk_2pow - pagesize_2pow));
	arena_maxclass = (chunk_size >> 1);

	UTRACE(0, 0, 0);

#ifdef MALLOC_STATS
	memset(&stats_chunks, 0, sizeof(chunk_stats_t));
#endif

	/* Various sanity checks that regard configuration. */
	assert(quantum >= sizeof(void *));
	assert(quantum <= pagesize);
	assert(chunk_size >= pagesize);
	assert(quantum * 4 <= chunk_size);

	/* Initialize chunks data. */
	malloc_mutex_init(&chunks_mtx);
	RB_INIT(&huge);
#ifdef USE_BRK
	brk_base = sbrk(0);
	brk_prev = brk_base;
	brk_max = (void *)((uintptr_t)brk_base + MAXDSIZ);
#endif
#ifdef MALLOC_STATS
	huge_nmalloc = 0;
	huge_ndalloc = 0;
	huge_allocated = 0;
#endif
	RB_INIT(&old_chunks);

	/* Initialize base allocation data structures. */
	base_chunk = NULL;
	base_next_addr = NULL;
	base_past_addr = NULL;
	base_chunk_nodes = NULL;
	malloc_mutex_init(&base_mtx);
#ifdef MALLOC_STATS
	base_total = 0;
#endif

	if (ncpus > 1) {
		/* 
		 * For SMP systems, create four times as many arenas as there
		 * are CPUs by default.
		 */
		opt_narenas_lshift += 2;
	}

	/* Determine how many arenas to use. */
	narenas = ncpus;
	if (opt_narenas_lshift > 0)
		narenas <<= opt_narenas_lshift;

#ifdef NO_TLS
	if (narenas > 1) {
		static const unsigned primes[] = {1, 3, 5, 7, 11, 13, 17, 19,
		    23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
		    89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
		    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
		    223, 227, 229, 233, 239, 241, 251, 257, 263};
		unsigned i, nprimes, parenas;

		/*
		 * Pick a prime number of hash arenas that is more than narenas
		 * so that direct hashing of pthread_self() pointers tends to
		 * spread allocations evenly among the arenas.
		 */
		assert((narenas & 1) == 0); /* narenas must be even. */
		nprimes = sizeof(primes) / sizeof(unsigned);
		parenas = primes[nprimes - 1]; /* In case not enough primes. */
		for (i = 1; i < nprimes; i++) {
			if (primes[i] > narenas) {
				parenas = primes[i];
				break;
			}
		}
		narenas = parenas;
	}
#endif

#ifndef NO_TLS
	next_arena = 0;
#endif

	/* Allocate and initialize arenas. */
	arenas = (arena_t **)base_alloc(sizeof(arena_t *) * narenas);
	if (arenas == NULL)
		return (true);
	/*
	 * Zero the array.  In practice, this should always be pre-zeroed,
	 * since it was just mmap()ed, but let's be sure.
	 */
	memset(arenas, 0, sizeof(arena_t *) * narenas);

	/*
	 * Initialize one arena here.  The rest are lazily created in
	 * arena_choose_hard().
	 */
	arenas_extend(0);
	if (arenas[0] == NULL)
		return (true);

	malloc_mutex_init(&arenas_mtx);

	malloc_initialized = true;
	return (false);
}

/*
 * End general internal functions.
 */
/******************************************************************************/
/*
 * Begin malloc(3)-compatible functions.
 */

void *
malloc(size_t size)
{
	void *ret;
	arena_t *arena;

	if (malloc_init()) {
		ret = NULL;
		goto RETURN;
	}

	if (size == 0) {
		if (opt_sysv == false)
			ret = &nil;
		else
			ret = NULL;
		goto RETURN;
	}

	arena = choose_arena();
	if (arena != NULL)
		ret = imalloc(arena, size);
	else
		ret = NULL;

RETURN:
	if (ret == NULL) {
		if (opt_xmalloc) {
			malloc_printf("%s: (malloc) Error in malloc(%zu):"
			    " out of memory\n", _getprogname(), size);
			abort();
		}
		errno = ENOMEM;
	}

	UTRACE(0, size, ret);
	return (ret);
}

int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret;
	arena_t *arena;
	void *result;

	if (malloc_init())
		result = NULL;
	else {
		/* Make sure that alignment is a large enough power of 2. */
		if (((alignment - 1) & alignment) != 0
		    || alignment < sizeof(void *)) {
			if (opt_xmalloc) {
				malloc_printf("%s: (malloc) Error in"
				    " posix_memalign(%zu, %zu):"
				    " invalid alignment\n",
				    _getprogname(), alignment, size);
				abort();
			}
			result = NULL;
			ret = EINVAL;
			goto RETURN;
		}

		arena = choose_arena();
		if (arena != NULL)
			result = ipalloc(arena, alignment, size);
		else
			result = NULL;
	}

	if (result == NULL) {
		if (opt_xmalloc) {
			malloc_printf("%s: (malloc) Error in"
			    " posix_memalign(%zu, %zu): out of memory\n",
			    _getprogname(), alignment, size);
			abort();
		}
		ret = ENOMEM;
		goto RETURN;
	}

	*memptr = result;
	ret = 0;

RETURN:
	UTRACE(0, size, result);
	return (ret);
}

void *
calloc(size_t num, size_t size)
{
	void *ret;
	arena_t *arena;

	if (malloc_init()) {
		ret = NULL;
		goto RETURN;
	}

	if (num * size == 0) {
		if (opt_sysv == false)
			ret = &nil;
		else
			ret = NULL;
		goto RETURN;
	} else if ((num * size) / size != num) {
		/* size_t overflow. */
		ret = NULL;
		goto RETURN;
	}

	arena = choose_arena();
	if (arena != NULL)
		ret = icalloc(arena, num * size);
	else
		ret = NULL;

RETURN:
	if (ret == NULL) {
		if (opt_xmalloc) {
			malloc_printf("%s: (malloc) Error in"
			    " calloc(%zu, %zu): out of memory\n", 
			    _getprogname(), num, size);
			abort();
		}
		errno = ENOMEM;
	}

	UTRACE(0, num * size, ret);
	return (ret);
}

void *
realloc(void *ptr, size_t size)
{
	void *ret;

	if (size != 0) {
		arena_t *arena;

		if (ptr != &nil && ptr != NULL) {
			assert(malloc_initialized);

			arena = choose_arena();
			if (arena != NULL)
				ret = iralloc(arena, ptr, size);
			else
				ret = NULL;

			if (ret == NULL) {
				if (opt_xmalloc) {
					malloc_printf("%s: (malloc) Error in"
					    " ralloc(%p, %zu): out of memory\n",
					    _getprogname(), ptr, size);
					abort();
				}
				errno = ENOMEM;
			}
		} else {
			if (malloc_init())
				ret = NULL;
			else {
				arena = choose_arena();
				if (arena != NULL)
					ret = imalloc(arena, size);
				else
					ret = NULL;
			}

			if (ret == NULL) {
				if (opt_xmalloc) {
					malloc_printf("%s: (malloc) Error in"
					    " ralloc(%p, %zu): out of memory\n",
					    _getprogname(), ptr, size);
					abort();
				}
				errno = ENOMEM;
			}
		}
	} else {
		if (ptr != &nil && ptr != NULL)
			idalloc(ptr);

		ret = &nil;
	}

	UTRACE(ptr, size, ret);
	return (ret);
}

void
free(void *ptr)
{

	UTRACE(ptr, 0, 0);
	if (ptr != &nil && ptr != NULL) {
		assert(malloc_initialized);

		idalloc(ptr);
	}
}

/*
 * End malloc(3)-compatible functions.
 */
/******************************************************************************/
/*
 * Begin library-private functions, used by threading libraries for protection
 * of malloc during fork().  These functions are only called if the program is
 * running in threaded mode, so there is no need to check whether the program
 * is threaded here.
 */

void
_malloc_prefork(void)
{
	unsigned i;

	/* Acquire all mutexes in a safe order. */

	malloc_mutex_lock(&arenas_mtx);
	for (i = 0; i < narenas; i++) {
		if (arenas[i] != NULL)
			malloc_mutex_lock(&arenas[i]->mtx);
	}
	malloc_mutex_unlock(&arenas_mtx);

	malloc_mutex_lock(&base_mtx);

	malloc_mutex_lock(&chunks_mtx);
}

void
_malloc_postfork(void)
{
	unsigned i;

	/* Release all mutexes, now that fork() has completed. */

	malloc_mutex_unlock(&chunks_mtx);

	malloc_mutex_unlock(&base_mtx);

	malloc_mutex_lock(&arenas_mtx);
	for (i = 0; i < narenas; i++) {
		if (arenas[i] != NULL)
			malloc_mutex_unlock(&arenas[i]->mtx);
	}
	malloc_mutex_unlock(&arenas_mtx);
}

/*
 * End library-private functions.
 */
/******************************************************************************/
