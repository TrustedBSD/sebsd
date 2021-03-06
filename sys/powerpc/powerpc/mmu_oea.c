/*-
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas <matt@3am-software.com> of Allegro Networks, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*-
 * Copyright (C) 1995, 1996 Wolfgang Solfrank.
 * Copyright (C) 1995, 1996 TooLs GmbH.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $NetBSD: pmap.c,v 1.28 2000/03/26 20:42:36 kleink Exp $
 */
/*-
 * Copyright (C) 2001 Benno Rice.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Benno Rice ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/powerpc/powerpc/mmu_oea.c,v 1.103 2005/11/08 06:49:45 grehan Exp $");

/*
 * Manages physical address maps.
 *
 * In addition to hardware address maps, this module is called upon to
 * provide software-use-only maps which may or may not be stored in the
 * same form as hardware maps.  These pseudo-maps are used to store
 * intermediate results from copy operations to and from address spaces.
 *
 * Since the information managed by this module is also stored by the
 * logical address mapping module, this module may throw away valid virtual
 * to physical mappings at almost any time.  However, invalidations of
 * mappings must be done as requested.
 *
 * In order to cope with hardware architectures which make virtual to
 * physical map invalidates expensive, this module may delay invalidate
 * reduced protection operations until such time as they are actually
 * necessary.  This module is given full information as to which processors
 * are currently using which maps, and to when physical maps must be made
 * correct.
 */

#include "opt_kstack_pages.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/msgbuf.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/vmmeter.h>

#include <dev/ofw/openfirm.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/uma.h>

#include <machine/cpu.h>
#include <machine/powerpc.h>
#include <machine/bat.h>
#include <machine/frame.h>
#include <machine/md_var.h>
#include <machine/psl.h>
#include <machine/pte.h>
#include <machine/sr.h>
#include <machine/mmuvar.h>

#include "mmu_if.h"

#define	MOEA_DEBUG

#define TODO	panic("%s: not implemented", __func__);

#define	TLBIE(va)	__asm __volatile("tlbie %0" :: "r"(va))
#define	TLBSYNC()	__asm __volatile("tlbsync");
#define	SYNC()		__asm __volatile("sync");
#define	EIEIO()		__asm __volatile("eieio");

#define	VSID_MAKE(sr, hash)	((sr) | (((hash) & 0xfffff) << 4))
#define	VSID_TO_SR(vsid)	((vsid) & 0xf)
#define	VSID_TO_HASH(vsid)	(((vsid) >> 4) & 0xfffff)

#define	PVO_PTEGIDX_MASK	0x007		/* which PTEG slot */
#define	PVO_PTEGIDX_VALID	0x008		/* slot is valid */
#define	PVO_WIRED		0x010		/* PVO entry is wired */
#define	PVO_MANAGED		0x020		/* PVO entry is managed */
#define	PVO_EXECUTABLE		0x040		/* PVO entry is executable */
#define	PVO_BOOTSTRAP		0x080		/* PVO entry allocated during
						   bootstrap */
#define PVO_FAKE		0x100		/* fictitious phys page */
#define	PVO_VADDR(pvo)		((pvo)->pvo_vaddr & ~ADDR_POFF)
#define	PVO_ISEXECUTABLE(pvo)	((pvo)->pvo_vaddr & PVO_EXECUTABLE)
#define PVO_ISFAKE(pvo)		((pvo)->pvo_vaddr & PVO_FAKE)
#define	PVO_PTEGIDX_GET(pvo)	((pvo)->pvo_vaddr & PVO_PTEGIDX_MASK)
#define	PVO_PTEGIDX_ISSET(pvo)	((pvo)->pvo_vaddr & PVO_PTEGIDX_VALID)
#define	PVO_PTEGIDX_CLR(pvo)	\
	((void)((pvo)->pvo_vaddr &= ~(PVO_PTEGIDX_VALID|PVO_PTEGIDX_MASK)))
#define	PVO_PTEGIDX_SET(pvo, i)	\
	((void)((pvo)->pvo_vaddr |= (i)|PVO_PTEGIDX_VALID))

#define	MOEA_PVO_CHECK(pvo)

struct ofw_map {
	vm_offset_t	om_va;
	vm_size_t	om_len;
	vm_offset_t	om_pa;
	u_int		om_mode;
};

/*
 * Map of physical memory regions.
 */
static struct	mem_region *regions;
static struct	mem_region *pregions;
u_int           phys_avail_count;
int		regions_sz, pregions_sz;
static struct	ofw_map *translations;

extern struct pmap ofw_pmap;



/*
 * Lock for the pteg and pvo tables.
 */
struct mtx	moea_table_mutex;

/*
 * PTEG data.
 */
static struct	pteg *moea_pteg_table;
u_int		moea_pteg_count;
u_int		moea_pteg_mask;

/*
 * PVO data.
 */
struct	pvo_head *moea_pvo_table;		/* pvo entries by pteg index */
struct	pvo_head moea_pvo_kunmanaged =
    LIST_HEAD_INITIALIZER(moea_pvo_kunmanaged);	/* list of unmanaged pages */
struct	pvo_head moea_pvo_unmanaged =
    LIST_HEAD_INITIALIZER(moea_pvo_unmanaged);	/* list of unmanaged pages */

uma_zone_t	moea_upvo_zone;	/* zone for pvo entries for unmanaged pages */
uma_zone_t	moea_mpvo_zone;	/* zone for pvo entries for managed pages */

#define	BPVO_POOL_SIZE	32768
static struct	pvo_entry *moea_bpvo_pool;
static int	moea_bpvo_pool_index = 0;

#define	VSID_NBPW	(sizeof(u_int32_t) * 8)
static u_int	moea_vsid_bitmap[NPMAPS / VSID_NBPW];

static boolean_t moea_initialized = FALSE;

/*
 * Statistics.
 */
u_int	moea_pte_valid = 0;
u_int	moea_pte_overflow = 0;
u_int	moea_pte_replacements = 0;
u_int	moea_pvo_entries = 0;
u_int	moea_pvo_enter_calls = 0;
u_int	moea_pvo_remove_calls = 0;
u_int	moea_pte_spills = 0;
SYSCTL_INT(_machdep, OID_AUTO, moea_pte_valid, CTLFLAG_RD, &moea_pte_valid,
    0, "");
SYSCTL_INT(_machdep, OID_AUTO, moea_pte_overflow, CTLFLAG_RD,
    &moea_pte_overflow, 0, "");
SYSCTL_INT(_machdep, OID_AUTO, moea_pte_replacements, CTLFLAG_RD,
    &moea_pte_replacements, 0, "");
SYSCTL_INT(_machdep, OID_AUTO, moea_pvo_entries, CTLFLAG_RD, &moea_pvo_entries,
    0, "");
SYSCTL_INT(_machdep, OID_AUTO, moea_pvo_enter_calls, CTLFLAG_RD,
    &moea_pvo_enter_calls, 0, "");
SYSCTL_INT(_machdep, OID_AUTO, moea_pvo_remove_calls, CTLFLAG_RD,
    &moea_pvo_remove_calls, 0, "");
SYSCTL_INT(_machdep, OID_AUTO, moea_pte_spills, CTLFLAG_RD,
    &moea_pte_spills, 0, "");

struct	pvo_entry *moea_pvo_zeropage;

vm_offset_t	moea_rkva_start = VM_MIN_KERNEL_ADDRESS;
u_int		moea_rkva_count = 4;

/*
 * Allocate physical memory for use in moea_bootstrap.
 */
static vm_offset_t	moea_bootstrap_alloc(vm_size_t, u_int);

/*
 * PTE calls.
 */
static int		moea_pte_insert(u_int, struct pte *);

/*
 * PVO calls.
 */
static int	moea_pvo_enter(pmap_t, uma_zone_t, struct pvo_head *,
		    vm_offset_t, vm_offset_t, u_int, int);
static void	moea_pvo_remove(struct pvo_entry *, int);
static struct	pvo_entry *moea_pvo_find_va(pmap_t, vm_offset_t, int *);
static struct	pte *moea_pvo_to_pte(const struct pvo_entry *, int);

/*
 * Utility routines.
 */
static struct		pvo_entry *moea_rkva_alloc(mmu_t);
static void		moea_pa_map(struct pvo_entry *, vm_offset_t,
			    struct pte *, int *);
static void		moea_pa_unmap(struct pvo_entry *, struct pte *, int *);
static void		moea_syncicache(vm_offset_t, vm_size_t);
static boolean_t	moea_query_bit(vm_page_t, int);
static u_int		moea_clear_bit(vm_page_t, int, int *);
static void		moea_kremove(mmu_t, vm_offset_t);
static void		tlbia(void);
int		moea_pte_spill(vm_offset_t);

/*
 * Kernel MMU interface
 */
void moea_change_wiring(mmu_t, pmap_t, vm_offset_t, boolean_t);
void moea_clear_modify(mmu_t, vm_page_t);
void moea_clear_reference(mmu_t, vm_page_t);
void moea_copy_page(mmu_t, vm_page_t, vm_page_t);
void moea_enter(mmu_t, pmap_t, vm_offset_t, vm_page_t, vm_prot_t, boolean_t);
vm_page_t moea_enter_quick(mmu_t, pmap_t, vm_offset_t, vm_page_t, vm_prot_t,
    vm_page_t);
vm_paddr_t moea_extract(mmu_t, pmap_t, vm_offset_t);
vm_page_t moea_extract_and_hold(mmu_t, pmap_t, vm_offset_t, vm_prot_t);
void moea_init(mmu_t);
boolean_t moea_is_modified(mmu_t, vm_page_t);
boolean_t moea_ts_referenced(mmu_t, vm_page_t);
vm_offset_t moea_map(mmu_t, vm_offset_t *, vm_offset_t, vm_offset_t, int);
boolean_t moea_page_exists_quick(mmu_t, pmap_t, vm_page_t);
void moea_page_protect(mmu_t, vm_page_t, vm_prot_t);
void moea_pinit(mmu_t, pmap_t);
void moea_pinit0(mmu_t, pmap_t);
void moea_protect(mmu_t, pmap_t, vm_offset_t, vm_offset_t, vm_prot_t);
void moea_qenter(mmu_t, vm_offset_t, vm_page_t *, int);
void moea_qremove(mmu_t, vm_offset_t, int);
void moea_release(mmu_t, pmap_t);
void moea_remove(mmu_t, pmap_t, vm_offset_t, vm_offset_t);
void moea_remove_all(mmu_t, vm_page_t);
void moea_zero_page(mmu_t, vm_page_t);
void moea_zero_page_area(mmu_t, vm_page_t, int, int);
void moea_zero_page_idle(mmu_t, vm_page_t);
void moea_activate(mmu_t, struct thread *);
void moea_deactivate(mmu_t, struct thread *);
void moea_bootstrap(mmu_t, vm_offset_t, vm_offset_t);
void *moea_mapdev(mmu_t, vm_offset_t, vm_size_t);
void moea_unmapdev(mmu_t, vm_offset_t, vm_size_t);
vm_offset_t moea_kextract(mmu_t, vm_offset_t);
void moea_kenter(mmu_t, vm_offset_t, vm_offset_t);
boolean_t moea_dev_direct_mapped(mmu_t, vm_offset_t, vm_size_t);

static mmu_method_t moea_methods[] = {
	MMUMETHOD(mmu_change_wiring,	moea_change_wiring),
	MMUMETHOD(mmu_clear_modify,	moea_clear_modify),
	MMUMETHOD(mmu_clear_reference,	moea_clear_reference),
	MMUMETHOD(mmu_copy_page,	moea_copy_page),
	MMUMETHOD(mmu_enter,		moea_enter),
	MMUMETHOD(mmu_enter_quick,	moea_enter_quick),
	MMUMETHOD(mmu_extract,		moea_extract),
	MMUMETHOD(mmu_extract_and_hold,	moea_extract_and_hold),
	MMUMETHOD(mmu_init,		moea_init),
	MMUMETHOD(mmu_is_modified,	moea_is_modified),
	MMUMETHOD(mmu_ts_referenced,	moea_ts_referenced),
	MMUMETHOD(mmu_map,     		moea_map),
	MMUMETHOD(mmu_page_exists_quick,moea_page_exists_quick),
	MMUMETHOD(mmu_page_protect,    	moea_page_protect),
	MMUMETHOD(mmu_pinit,		moea_pinit),
	MMUMETHOD(mmu_pinit0,		moea_pinit0),
	MMUMETHOD(mmu_protect,		moea_protect),
	MMUMETHOD(mmu_qenter,		moea_qenter),
	MMUMETHOD(mmu_qremove,		moea_qremove),
	MMUMETHOD(mmu_release,		moea_release),
	MMUMETHOD(mmu_remove,		moea_remove),
	MMUMETHOD(mmu_remove_all,      	moea_remove_all),
	MMUMETHOD(mmu_zero_page,       	moea_zero_page),
	MMUMETHOD(mmu_zero_page_area,	moea_zero_page_area),
	MMUMETHOD(mmu_zero_page_idle,	moea_zero_page_idle),
	MMUMETHOD(mmu_activate,		moea_activate),
	MMUMETHOD(mmu_deactivate,      	moea_deactivate),

	/* Internal interfaces */
	MMUMETHOD(mmu_bootstrap,       	moea_bootstrap),
	MMUMETHOD(mmu_mapdev,		moea_mapdev),
	MMUMETHOD(mmu_unmapdev,		moea_unmapdev),
	MMUMETHOD(mmu_kextract,		moea_kextract),
	MMUMETHOD(mmu_kenter,		moea_kenter),
	MMUMETHOD(mmu_dev_direct_mapped,moea_dev_direct_mapped),

	{ 0, 0 }
};

static mmu_def_t oea_mmu = {
	MMU_TYPE_OEA,
	moea_methods,
	0
};
MMU_DEF(oea_mmu);


static __inline int
va_to_sr(u_int *sr, vm_offset_t va)
{
	return (sr[(uintptr_t)va >> ADDR_SR_SHFT]);
}

static __inline u_int
va_to_pteg(u_int sr, vm_offset_t addr)
{
	u_int hash;

	hash = (sr & SR_VSID_MASK) ^ (((u_int)addr & ADDR_PIDX) >>
	    ADDR_PIDX_SHFT);
	return (hash & moea_pteg_mask);
}

static __inline struct pvo_head *
pa_to_pvoh(vm_offset_t pa, vm_page_t *pg_p)
{
	struct	vm_page *pg;

	pg = PHYS_TO_VM_PAGE(pa);

	if (pg_p != NULL)
		*pg_p = pg;

	if (pg == NULL)
		return (&moea_pvo_unmanaged);

	return (&pg->md.mdpg_pvoh);
}

static __inline struct pvo_head *
vm_page_to_pvoh(vm_page_t m)
{

	return (&m->md.mdpg_pvoh);
}

static __inline void
moea_attr_clear(vm_page_t m, int ptebit)
{

	m->md.mdpg_attrs &= ~ptebit;
}

static __inline int
moea_attr_fetch(vm_page_t m)
{

	return (m->md.mdpg_attrs);
}

static __inline void
moea_attr_save(vm_page_t m, int ptebit)
{

	m->md.mdpg_attrs |= ptebit;
}

static __inline int
moea_pte_compare(const struct pte *pt, const struct pte *pvo_pt)
{
	if (pt->pte_hi == pvo_pt->pte_hi)
		return (1);

	return (0);
}

static __inline int
moea_pte_match(struct pte *pt, u_int sr, vm_offset_t va, int which)
{
	return (pt->pte_hi & ~PTE_VALID) ==
	    (((sr & SR_VSID_MASK) << PTE_VSID_SHFT) |
	    ((va >> ADDR_API_SHFT) & PTE_API) | which);
}

static __inline void
moea_pte_create(struct pte *pt, u_int sr, vm_offset_t va, u_int pte_lo)
{
	/*
	 * Construct a PTE.  Default to IMB initially.  Valid bit only gets
	 * set when the real pte is set in memory.
	 *
	 * Note: Don't set the valid bit for correct operation of tlb update.
	 */
	pt->pte_hi = ((sr & SR_VSID_MASK) << PTE_VSID_SHFT) |
	    (((va & ADDR_PIDX) >> ADDR_API_SHFT) & PTE_API);
	pt->pte_lo = pte_lo;
}

static __inline void
moea_pte_synch(struct pte *pt, struct pte *pvo_pt)
{

	pvo_pt->pte_lo |= pt->pte_lo & (PTE_REF | PTE_CHG);
}

static __inline void
moea_pte_clear(struct pte *pt, vm_offset_t va, int ptebit)
{

	/*
	 * As shown in Section 7.6.3.2.3
	 */
	pt->pte_lo &= ~ptebit;
	TLBIE(va);
	EIEIO();
	TLBSYNC();
	SYNC();
}

static __inline void
moea_pte_set(struct pte *pt, struct pte *pvo_pt)
{

	pvo_pt->pte_hi |= PTE_VALID;

	/*
	 * Update the PTE as defined in section 7.6.3.1.
	 * Note that the REF/CHG bits are from pvo_pt and thus should havce
	 * been saved so this routine can restore them (if desired).
	 */
	pt->pte_lo = pvo_pt->pte_lo;
	EIEIO();
	pt->pte_hi = pvo_pt->pte_hi;
	SYNC();
	moea_pte_valid++;
}

static __inline void
moea_pte_unset(struct pte *pt, struct pte *pvo_pt, vm_offset_t va)
{

	pvo_pt->pte_hi &= ~PTE_VALID;

	/*
	 * Force the reg & chg bits back into the PTEs.
	 */
	SYNC();

	/*
	 * Invalidate the pte.
	 */
	pt->pte_hi &= ~PTE_VALID;

	SYNC();
	TLBIE(va);
	EIEIO();
	TLBSYNC();
	SYNC();

	/*
	 * Save the reg & chg bits.
	 */
	moea_pte_synch(pt, pvo_pt);
	moea_pte_valid--;
}

static __inline void
moea_pte_change(struct pte *pt, struct pte *pvo_pt, vm_offset_t va)
{

	/*
	 * Invalidate the PTE
	 */
	moea_pte_unset(pt, pvo_pt, va);
	moea_pte_set(pt, pvo_pt);
}

/*
 * Quick sort callout for comparing memory regions.
 */
static int	mr_cmp(const void *a, const void *b);
static int	om_cmp(const void *a, const void *b);

static int
mr_cmp(const void *a, const void *b)
{
	const struct	mem_region *regiona;
	const struct	mem_region *regionb;

	regiona = a;
	regionb = b;
	if (regiona->mr_start < regionb->mr_start)
		return (-1);
	else if (regiona->mr_start > regionb->mr_start)
		return (1);
	else
		return (0);
}

static int
om_cmp(const void *a, const void *b)
{
	const struct	ofw_map *mapa;
	const struct	ofw_map *mapb;

	mapa = a;
	mapb = b;
	if (mapa->om_pa < mapb->om_pa)
		return (-1);
	else if (mapa->om_pa > mapb->om_pa)
		return (1);
	else
		return (0);
}

void
moea_bootstrap(mmu_t mmup, vm_offset_t kernelstart, vm_offset_t kernelend)
{
	ihandle_t	mmui;
	phandle_t	chosen, mmu;
	int		sz;
	int		i, j;
	int		ofw_mappings;
	vm_size_t	size, physsz, hwphyssz;
	vm_offset_t	pa, va, off;
	u_int		batl, batu;

        /*
         * Set up BAT0 to map the lowest 256 MB area
         */
        battable[0x0].batl = BATL(0x00000000, BAT_M, BAT_PP_RW);
        battable[0x0].batu = BATU(0x00000000, BAT_BL_256M, BAT_Vs);

        /*
         * Map PCI memory space.
         */
        battable[0x8].batl = BATL(0x80000000, BAT_I|BAT_G, BAT_PP_RW);
        battable[0x8].batu = BATU(0x80000000, BAT_BL_256M, BAT_Vs);

        battable[0x9].batl = BATL(0x90000000, BAT_I|BAT_G, BAT_PP_RW);
        battable[0x9].batu = BATU(0x90000000, BAT_BL_256M, BAT_Vs);

        battable[0xa].batl = BATL(0xa0000000, BAT_I|BAT_G, BAT_PP_RW);
        battable[0xa].batu = BATU(0xa0000000, BAT_BL_256M, BAT_Vs);

        battable[0xb].batl = BATL(0xb0000000, BAT_I|BAT_G, BAT_PP_RW);
        battable[0xb].batu = BATU(0xb0000000, BAT_BL_256M, BAT_Vs);

        /*
         * Map obio devices.
         */
        battable[0xf].batl = BATL(0xf0000000, BAT_I|BAT_G, BAT_PP_RW);
        battable[0xf].batu = BATU(0xf0000000, BAT_BL_256M, BAT_Vs);

	/*
	 * Use an IBAT and a DBAT to map the bottom segment of memory
	 * where we are.
	 */
	batu = BATU(0x00000000, BAT_BL_256M, BAT_Vs);
	batl = BATL(0x00000000, BAT_M, BAT_PP_RW);
	__asm (".balign 32; \n"
	       "mtibatu 0,%0; mtibatl 0,%1; isync; \n"
	       "mtdbatu 0,%0; mtdbatl 0,%1; isync"
	    :: "r"(batu), "r"(batl));

#if 0
	/* map frame buffer */
	batu = BATU(0x90000000, BAT_BL_256M, BAT_Vs);
	batl = BATL(0x90000000, BAT_I|BAT_G, BAT_PP_RW);
	__asm ("mtdbatu 1,%0; mtdbatl 1,%1; isync"
	    :: "r"(batu), "r"(batl));
#endif

#if 1
	/* map pci space */
	batu = BATU(0x80000000, BAT_BL_256M, BAT_Vs);
	batl = BATL(0x80000000, BAT_I|BAT_G, BAT_PP_RW);
	__asm ("mtdbatu 1,%0; mtdbatl 1,%1; isync"
	    :: "r"(batu), "r"(batl));
#endif

	/*
	 * Set the start and end of kva.
	 */
	virtual_avail = VM_MIN_KERNEL_ADDRESS;
	virtual_end = VM_MAX_KERNEL_ADDRESS;

	mem_regions(&pregions, &pregions_sz, &regions, &regions_sz);
	CTR0(KTR_PMAP, "moea_bootstrap: physical memory");

	qsort(pregions, pregions_sz, sizeof(*pregions), mr_cmp);
	for (i = 0; i < pregions_sz; i++) {
		vm_offset_t pa;
		vm_offset_t end;

		CTR3(KTR_PMAP, "physregion: %#x - %#x (%#x)",
			pregions[i].mr_start,
			pregions[i].mr_start + pregions[i].mr_size,
			pregions[i].mr_size);
		/*
		 * Install entries into the BAT table to allow all
		 * of physmem to be convered by on-demand BAT entries.
		 * The loop will sometimes set the same battable element
		 * twice, but that's fine since they won't be used for
		 * a while yet.
		 */
		pa = pregions[i].mr_start & 0xf0000000;
		end = pregions[i].mr_start + pregions[i].mr_size;
		do {
                        u_int n = pa >> ADDR_SR_SHFT;

			battable[n].batl = BATL(pa, BAT_M, BAT_PP_RW);
			battable[n].batu = BATU(pa, BAT_BL_256M, BAT_Vs);
			pa += SEGMENT_LENGTH;
		} while (pa < end);
	}

	if (sizeof(phys_avail)/sizeof(phys_avail[0]) < regions_sz)
		panic("moea_bootstrap: phys_avail too small");
	qsort(regions, regions_sz, sizeof(*regions), mr_cmp);
	phys_avail_count = 0;
	physsz = 0;
	hwphyssz = 0;
	TUNABLE_ULONG_FETCH("hw.physmem", (u_long *) &hwphyssz);
	for (i = 0, j = 0; i < regions_sz; i++, j += 2) {
		CTR3(KTR_PMAP, "region: %#x - %#x (%#x)", regions[i].mr_start,
		    regions[i].mr_start + regions[i].mr_size,
		    regions[i].mr_size);
		if (hwphyssz != 0 &&
		    (physsz + regions[i].mr_size) >= hwphyssz) {
			if (physsz < hwphyssz) {
				phys_avail[j] = regions[i].mr_start;
				phys_avail[j + 1] = regions[i].mr_start +
				    hwphyssz - physsz;
				physsz = hwphyssz;
				phys_avail_count++;
			}
			break;
		}
		phys_avail[j] = regions[i].mr_start;
		phys_avail[j + 1] = regions[i].mr_start + regions[i].mr_size;
		phys_avail_count++;
		physsz += regions[i].mr_size;
	}
	physmem = btoc(physsz);

	/*
	 * Allocate PTEG table.
	 */
#ifdef PTEGCOUNT
	moea_pteg_count = PTEGCOUNT;
#else
	moea_pteg_count = 0x1000;

	while (moea_pteg_count < physmem)
		moea_pteg_count <<= 1;

	moea_pteg_count >>= 1;
#endif /* PTEGCOUNT */

	size = moea_pteg_count * sizeof(struct pteg);
	CTR2(KTR_PMAP, "moea_bootstrap: %d PTEGs, %d bytes", moea_pteg_count,
	    size);
	moea_pteg_table = (struct pteg *)moea_bootstrap_alloc(size, size);
	CTR1(KTR_PMAP, "moea_bootstrap: PTEG table at %p", moea_pteg_table);
	bzero((void *)moea_pteg_table, moea_pteg_count * sizeof(struct pteg));
	moea_pteg_mask = moea_pteg_count - 1;

	/*
	 * Allocate pv/overflow lists.
	 */
	size = sizeof(struct pvo_head) * moea_pteg_count;
	moea_pvo_table = (struct pvo_head *)moea_bootstrap_alloc(size,
	    PAGE_SIZE);
	CTR1(KTR_PMAP, "moea_bootstrap: PVO table at %p", moea_pvo_table);
	for (i = 0; i < moea_pteg_count; i++)
		LIST_INIT(&moea_pvo_table[i]);

	/*
	 * Initialize the lock that synchronizes access to the pteg and pvo
	 * tables.
	 */
	mtx_init(&moea_table_mutex, "pmap table", NULL, MTX_DEF);

	/*
	 * Allocate the message buffer.
	 */
	msgbuf_phys = moea_bootstrap_alloc(MSGBUF_SIZE, 0);

	/*
	 * Initialise the unmanaged pvo pool.
	 */
	moea_bpvo_pool = (struct pvo_entry *)moea_bootstrap_alloc(
		BPVO_POOL_SIZE*sizeof(struct pvo_entry), 0);
	moea_bpvo_pool_index = 0;

	/*
	 * Make sure kernel vsid is allocated as well as VSID 0.
	 */
	moea_vsid_bitmap[(KERNEL_VSIDBITS & (NPMAPS - 1)) / VSID_NBPW]
		|= 1 << (KERNEL_VSIDBITS % VSID_NBPW);
	moea_vsid_bitmap[0] |= 1;

	/*
	 * Set up the Open Firmware pmap and add it's mappings.
	 */
	moea_pinit(mmup, &ofw_pmap);
	ofw_pmap.pm_sr[KERNEL_SR] = KERNEL_SEGMENT;
	ofw_pmap.pm_sr[KERNEL2_SR] = KERNEL2_SEGMENT;
	if ((chosen = OF_finddevice("/chosen")) == -1)
		panic("moea_bootstrap: can't find /chosen");
	OF_getprop(chosen, "mmu", &mmui, 4);
	if ((mmu = OF_instance_to_package(mmui)) == -1)
		panic("moea_bootstrap: can't get mmu package");
	if ((sz = OF_getproplen(mmu, "translations")) == -1)
		panic("moea_bootstrap: can't get ofw translation count");
	translations = NULL;
	for (i = 0; phys_avail[i] != 0; i += 2) {
		if (phys_avail[i + 1] >= sz) {
			translations = (struct ofw_map *)phys_avail[i];
			break;
		}
	}
	if (translations == NULL)
		panic("moea_bootstrap: no space to copy translations");
	bzero(translations, sz);
	if (OF_getprop(mmu, "translations", translations, sz) == -1)
		panic("moea_bootstrap: can't get ofw translations");
	CTR0(KTR_PMAP, "moea_bootstrap: translations");
	sz /= sizeof(*translations);
	qsort(translations, sz, sizeof (*translations), om_cmp);
	for (i = 0, ofw_mappings = 0; i < sz; i++) {
		CTR3(KTR_PMAP, "translation: pa=%#x va=%#x len=%#x",
		    translations[i].om_pa, translations[i].om_va,
		    translations[i].om_len);

		/*
		 * If the mapping is 1:1, let the RAM and device on-demand
		 * BAT tables take care of the translation.
		 */
		if (translations[i].om_va == translations[i].om_pa)
			continue;

		/* Enter the pages */
		for (off = 0; off < translations[i].om_len; off += PAGE_SIZE) {
			struct	vm_page m;

			m.phys_addr = translations[i].om_pa + off;
			moea_enter(mmup, &ofw_pmap,
				   translations[i].om_va + off, &m,
				   VM_PROT_ALL, 1);
			ofw_mappings++;
		}
	}
#ifdef SMP
	TLBSYNC();
#endif

	/*
	 * Initialize the kernel pmap (which is statically allocated).
	 */
	PMAP_LOCK_INIT(kernel_pmap);
	for (i = 0; i < 16; i++) {
		kernel_pmap->pm_sr[i] = EMPTY_SEGMENT;
	}
	kernel_pmap->pm_sr[KERNEL_SR] = KERNEL_SEGMENT;
	kernel_pmap->pm_sr[KERNEL2_SR] = KERNEL2_SEGMENT;
	kernel_pmap->pm_active = ~0;

	/*
	 * Allocate a kernel stack with a guard page for thread0 and map it
	 * into the kernel page map.
	 */
	pa = moea_bootstrap_alloc(KSTACK_PAGES * PAGE_SIZE, 0);
	kstack0_phys = pa;
	kstack0 = virtual_avail + (KSTACK_GUARD_PAGES * PAGE_SIZE);
	CTR2(KTR_PMAP, "moea_bootstrap: kstack0 at %#x (%#x)", kstack0_phys,
	    kstack0);
	virtual_avail += (KSTACK_PAGES + KSTACK_GUARD_PAGES) * PAGE_SIZE;
	for (i = 0; i < KSTACK_PAGES; i++) {
		pa = kstack0_phys + i * PAGE_SIZE;
		va = kstack0 + i * PAGE_SIZE;
		moea_kenter(mmup, va, pa);
		TLBIE(va);
	}

	/*
	 * Calculate the last available physical address.
	 */
	for (i = 0; phys_avail[i + 2] != 0; i += 2)
		;
	Maxmem = powerpc_btop(phys_avail[i + 1]);

	/*
	 * Allocate virtual address space for the message buffer.
	 */
	msgbufp = (struct msgbuf *)virtual_avail;
	virtual_avail += round_page(MSGBUF_SIZE);

	/*
	 * Initialize hardware.
	 */
	for (i = 0; i < 16; i++) {
		mtsrin(i << ADDR_SR_SHFT, EMPTY_SEGMENT);
	}
	__asm __volatile ("mtsr %0,%1"
	    :: "n"(KERNEL_SR), "r"(KERNEL_SEGMENT));
	__asm __volatile ("mtsr %0,%1"
	    :: "n"(KERNEL2_SR), "r"(KERNEL2_SEGMENT));
	__asm __volatile ("sync; mtsdr1 %0; isync"
	    :: "r"((u_int)moea_pteg_table | (moea_pteg_mask >> 10)));
	tlbia();

	pmap_bootstrapped++;
}

/*
 * Activate a user pmap.  The pmap must be activated before it's address
 * space can be accessed in any way.
 */
void
moea_activate(mmu_t mmu, struct thread *td)
{
	pmap_t	pm, pmr;

	/*
	 * Load all the data we need up front to encourage the compiler to
	 * not issue any loads while we have interrupts disabled below.
	 */
	pm = &td->td_proc->p_vmspace->vm_pmap;

	if ((pmr = (pmap_t)moea_kextract(mmu, (vm_offset_t)pm)) == NULL)
		pmr = pm;

	pm->pm_active |= PCPU_GET(cpumask);
	PCPU_SET(curpmap, pmr);
}

void
moea_deactivate(mmu_t mmu, struct thread *td)
{
	pmap_t	pm;

	pm = &td->td_proc->p_vmspace->vm_pmap;
	pm->pm_active &= ~(PCPU_GET(cpumask));
	PCPU_SET(curpmap, NULL);
}

void
moea_change_wiring(mmu_t mmu, pmap_t pm, vm_offset_t va, boolean_t wired)
{
	struct	pvo_entry *pvo;

	PMAP_LOCK(pm);
	pvo = moea_pvo_find_va(pm, va & ~ADDR_POFF, NULL);

	if (pvo != NULL) {
		if (wired) {
			if ((pvo->pvo_vaddr & PVO_WIRED) == 0)
				pm->pm_stats.wired_count++;
			pvo->pvo_vaddr |= PVO_WIRED;
		} else {
			if ((pvo->pvo_vaddr & PVO_WIRED) != 0)
				pm->pm_stats.wired_count--;
			pvo->pvo_vaddr &= ~PVO_WIRED;
		}
	}
	PMAP_UNLOCK(pm);
}

void
moea_copy_page(mmu_t mmu, vm_page_t msrc, vm_page_t mdst)
{
	vm_offset_t	dst;
	vm_offset_t	src;

	dst = VM_PAGE_TO_PHYS(mdst);
	src = VM_PAGE_TO_PHYS(msrc);

	kcopy((void *)src, (void *)dst, PAGE_SIZE);
}

/*
 * Zero a page of physical memory by temporarily mapping it into the tlb.
 */
void
moea_zero_page(mmu_t mmu, vm_page_t m)
{
	vm_offset_t pa = VM_PAGE_TO_PHYS(m);
	caddr_t va;

	if (pa < SEGMENT_LENGTH) {
		va = (caddr_t) pa;
	} else if (moea_initialized) {
		if (moea_pvo_zeropage == NULL)
			moea_pvo_zeropage = moea_rkva_alloc(mmu);
		moea_pa_map(moea_pvo_zeropage, pa, NULL, NULL);
		va = (caddr_t)PVO_VADDR(moea_pvo_zeropage);
	} else {
		panic("moea_zero_page: can't zero pa %#x", pa);
	}

	bzero(va, PAGE_SIZE);

	if (pa >= SEGMENT_LENGTH)
		moea_pa_unmap(moea_pvo_zeropage, NULL, NULL);
}

void
moea_zero_page_area(mmu_t mmu, vm_page_t m, int off, int size)
{
	vm_offset_t pa = VM_PAGE_TO_PHYS(m);
	caddr_t va;

	if (pa < SEGMENT_LENGTH) {
		va = (caddr_t) pa;
	} else if (moea_initialized) {
		if (moea_pvo_zeropage == NULL)
			moea_pvo_zeropage = moea_rkva_alloc(mmu);
		moea_pa_map(moea_pvo_zeropage, pa, NULL, NULL);
		va = (caddr_t)PVO_VADDR(moea_pvo_zeropage);
	} else {
		panic("moea_zero_page: can't zero pa %#x", pa);
	}

	bzero(va + off, size);

	if (pa >= SEGMENT_LENGTH)
		moea_pa_unmap(moea_pvo_zeropage, NULL, NULL);
}

void
moea_zero_page_idle(mmu_t mmu, vm_page_t m)
{

	/* XXX this is called outside of Giant, is moea_zero_page safe? */
	/* XXX maybe have a dedicated mapping for this to avoid the problem? */
	mtx_lock(&Giant);
	moea_zero_page(mmu, m);
	mtx_unlock(&Giant);
}

/*
 * Map the given physical page at the specified virtual address in the
 * target pmap with the protection requested.  If specified the page
 * will be wired down.
 */
void
moea_enter(mmu_t mmu, pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot,
	   boolean_t wired)
{
	struct		pvo_head *pvo_head;
	uma_zone_t	zone;
	vm_page_t	pg;
	u_int		pte_lo, pvo_flags, was_exec, i;
	int		error;

	if (!moea_initialized) {
		pvo_head = &moea_pvo_kunmanaged;
		zone = moea_upvo_zone;
		pvo_flags = 0;
		pg = NULL;
		was_exec = PTE_EXEC;
	} else {
		pvo_head = vm_page_to_pvoh(m);
		pg = m;
		zone = moea_mpvo_zone;
		pvo_flags = PVO_MANAGED;
		was_exec = 0;
	}
	if (pmap_bootstrapped)
		vm_page_lock_queues();
	PMAP_LOCK(pmap);

	/* XXX change the pvo head for fake pages */
	if ((m->flags & PG_FICTITIOUS) == PG_FICTITIOUS)
		pvo_head = &moea_pvo_kunmanaged;

	/*
	 * If this is a managed page, and it's the first reference to the page,
	 * clear the execness of the page.  Otherwise fetch the execness.
	 */
	if ((pg != NULL) && ((m->flags & PG_FICTITIOUS) == 0)) {
		if (LIST_EMPTY(pvo_head)) {
			moea_attr_clear(pg, PTE_EXEC);
		} else {
			was_exec = moea_attr_fetch(pg) & PTE_EXEC;
		}
	}

	/*
	 * Assume the page is cache inhibited and access is guarded unless
	 * it's in our available memory array.
	 */
	pte_lo = PTE_I | PTE_G;
	for (i = 0; i < pregions_sz; i++) {
		if ((VM_PAGE_TO_PHYS(m) >= pregions[i].mr_start) &&
		    (VM_PAGE_TO_PHYS(m) < 
			(pregions[i].mr_start + pregions[i].mr_size))) {
			pte_lo &= ~(PTE_I | PTE_G);
			break;
		}
	}

	if (prot & VM_PROT_WRITE)
		pte_lo |= PTE_BW;
	else
		pte_lo |= PTE_BR;

	if (prot & VM_PROT_EXECUTE)
		pvo_flags |= PVO_EXECUTABLE;

	if (wired)
		pvo_flags |= PVO_WIRED;

	if ((m->flags & PG_FICTITIOUS) != 0)
		pvo_flags |= PVO_FAKE;

	error = moea_pvo_enter(pmap, zone, pvo_head, va, VM_PAGE_TO_PHYS(m),
	    pte_lo, pvo_flags);

	/*
	 * Flush the real page from the instruction cache if this page is
	 * mapped executable and cacheable and was not previously mapped (or
	 * was not mapped executable).
	 */
	if (error == 0 && (pvo_flags & PVO_EXECUTABLE) &&
	    (pte_lo & PTE_I) == 0 && was_exec == 0) {
		/*
		 * Flush the real memory from the cache.
		 */
		moea_syncicache(VM_PAGE_TO_PHYS(m), PAGE_SIZE);
		if (pg != NULL)
			moea_attr_save(pg, PTE_EXEC);
	}
	if (pmap_bootstrapped)
		vm_page_unlock_queues();

	/* XXX syncicache always until problems are sorted */
	moea_syncicache(VM_PAGE_TO_PHYS(m), PAGE_SIZE);
	PMAP_UNLOCK(pmap);
}

vm_page_t
moea_enter_quick(mmu_t mmu, pmap_t pm, vm_offset_t va, vm_page_t m,
    vm_prot_t prot, vm_page_t mpte)
{

	vm_page_busy(m);
	vm_page_unlock_queues();
	VM_OBJECT_UNLOCK(m->object);
	mtx_lock(&Giant);
	moea_enter(mmu, pm, va, m, prot & (VM_PROT_READ | VM_PROT_EXECUTE),
	    FALSE);
	mtx_unlock(&Giant);
	VM_OBJECT_LOCK(m->object);
	vm_page_lock_queues();
	vm_page_wakeup(m);
	return (NULL);
}

vm_paddr_t
moea_extract(mmu_t mmu, pmap_t pm, vm_offset_t va)
{
	struct	pvo_entry *pvo;
	vm_paddr_t pa;

	PMAP_LOCK(pm);
	pvo = moea_pvo_find_va(pm, va & ~ADDR_POFF, NULL);
	if (pvo == NULL)
		pa = 0;
	else
		pa = (pvo->pvo_pte.pte_lo & PTE_RPGN) | (va & ADDR_POFF);
	PMAP_UNLOCK(pm);
	return (pa);
}

/*
 * Atomically extract and hold the physical page with the given
 * pmap and virtual address pair if that mapping permits the given
 * protection.
 */
vm_page_t
moea_extract_and_hold(mmu_t mmu, pmap_t pmap, vm_offset_t va, vm_prot_t prot)
{
	struct	pvo_entry *pvo;
	vm_page_t m;
        
	m = NULL;
	mtx_lock(&Giant);
	vm_page_lock_queues();
	PMAP_LOCK(pmap);
	pvo = moea_pvo_find_va(pmap, va & ~ADDR_POFF, NULL);
	if (pvo != NULL && (pvo->pvo_pte.pte_hi & PTE_VALID) &&
	    ((pvo->pvo_pte.pte_lo & PTE_PP) == PTE_RW ||
	     (prot & VM_PROT_WRITE) == 0)) {
		m = PHYS_TO_VM_PAGE(pvo->pvo_pte.pte_lo & PTE_RPGN);
		vm_page_hold(m);
	}
	vm_page_unlock_queues();
	PMAP_UNLOCK(pmap);
	mtx_unlock(&Giant);
	return (m);
}

void
moea_init(mmu_t mmu)
{

	CTR0(KTR_PMAP, "moea_init");

	moea_upvo_zone = uma_zcreate("UPVO entry", sizeof (struct pvo_entry),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,
	    UMA_ZONE_VM | UMA_ZONE_NOFREE);
	moea_mpvo_zone = uma_zcreate("MPVO entry", sizeof(struct pvo_entry),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,
	    UMA_ZONE_VM | UMA_ZONE_NOFREE);
	moea_initialized = TRUE;
}

boolean_t
moea_is_modified(mmu_t mmu, vm_page_t m)
{

	if ((m->flags & (PG_FICTITIOUS |PG_UNMANAGED)) != 0)
		return (FALSE);

	return (moea_query_bit(m, PTE_CHG));
}

void
moea_clear_reference(mmu_t mmu, vm_page_t m)
{

	if ((m->flags & (PG_FICTITIOUS | PG_UNMANAGED)) != 0)
		return;
	moea_clear_bit(m, PTE_REF, NULL);
}

void
moea_clear_modify(mmu_t mmu, vm_page_t m)
{

	if ((m->flags & (PG_FICTITIOUS | PG_UNMANAGED)) != 0)
		return;
	moea_clear_bit(m, PTE_CHG, NULL);
}

/*
 *	moea_ts_referenced:
 *
 *	Return a count of reference bits for a page, clearing those bits.
 *	It is not necessary for every reference bit to be cleared, but it
 *	is necessary that 0 only be returned when there are truly no
 *	reference bits set.
 *
 *	XXX: The exact number of bits to check and clear is a matter that
 *	should be tested and standardized at some point in the future for
 *	optimal aging of shared pages.
 */
boolean_t
moea_ts_referenced(mmu_t mmu, vm_page_t m)
{
	int count;

	if ((m->flags & (PG_FICTITIOUS | PG_UNMANAGED)) != 0)
		return (0);

	count = moea_clear_bit(m, PTE_REF, NULL);

	return (count);
}

/*
 * Map a wired page into kernel virtual address space.
 */
void
moea_kenter(mmu_t mmu, vm_offset_t va, vm_offset_t pa)
{
	u_int		pte_lo;
	int		error;	
	int		i;

#if 0
	if (va < VM_MIN_KERNEL_ADDRESS)
		panic("moea_kenter: attempt to enter non-kernel address %#x",
		    va);
#endif

	pte_lo = PTE_I | PTE_G;
	for (i = 0; i < pregions_sz; i++) {
		if ((pa >= pregions[i].mr_start) &&
		    (pa < (pregions[i].mr_start + pregions[i].mr_size))) {
			pte_lo &= ~(PTE_I | PTE_G);
			break;
		}
	}	

	PMAP_LOCK(kernel_pmap);
	error = moea_pvo_enter(kernel_pmap, moea_upvo_zone,
	    &moea_pvo_kunmanaged, va, pa, pte_lo, PVO_WIRED);

	if (error != 0 && error != ENOENT)
		panic("moea_kenter: failed to enter va %#x pa %#x: %d", va,
		    pa, error);

	/*
	 * Flush the real memory from the instruction cache.
	 */
	if ((pte_lo & (PTE_I | PTE_G)) == 0) {
		moea_syncicache(pa, PAGE_SIZE);
	}
	PMAP_UNLOCK(kernel_pmap);
}

/*
 * Extract the physical page address associated with the given kernel virtual
 * address.
 */
vm_offset_t
moea_kextract(mmu_t mmu, vm_offset_t va)
{
	struct		pvo_entry *pvo;
	vm_paddr_t pa;

#ifdef UMA_MD_SMALL_ALLOC
	/*
	 * Allow direct mappings
	 */
	if (va < VM_MIN_KERNEL_ADDRESS) {
		return (va);
	}
#endif

	PMAP_LOCK(kernel_pmap);
	pvo = moea_pvo_find_va(kernel_pmap, va & ~ADDR_POFF, NULL);
	KASSERT(pvo != NULL, ("moea_kextract: no addr found"));
	pa = (pvo->pvo_pte.pte_lo & PTE_RPGN) | (va & ADDR_POFF);
	PMAP_UNLOCK(kernel_pmap);
	return (pa);
}

/*
 * Remove a wired page from kernel virtual address space.
 */
void
moea_kremove(mmu_t mmu, vm_offset_t va)
{

	moea_remove(mmu, kernel_pmap, va, va + PAGE_SIZE);
}

/*
 * Map a range of physical addresses into kernel virtual address space.
 *
 * The value passed in *virt is a suggested virtual address for the mapping.
 * Architectures which can support a direct-mapped physical to virtual region
 * can return the appropriate address within that region, leaving '*virt'
 * unchanged.  We cannot and therefore do not; *virt is updated with the
 * first usable address after the mapped region.
 */
vm_offset_t
moea_map(mmu_t mmu, vm_offset_t *virt, vm_offset_t pa_start,
    vm_offset_t pa_end, int prot)
{
	vm_offset_t	sva, va;

	sva = *virt;
	va = sva;
	for (; pa_start < pa_end; pa_start += PAGE_SIZE, va += PAGE_SIZE)
		moea_kenter(mmu, va, pa_start);
	*virt = va;
	return (sva);
}

/*
 * Lower the permission for all mappings to a given page.
 */
void
moea_page_protect(mmu_t mmu, vm_page_t m, vm_prot_t prot)
{
	struct	pvo_head *pvo_head;
	struct	pvo_entry *pvo, *next_pvo;
	struct	pte *pt;
	pmap_t	pmap;

	/*
	 * Since the routine only downgrades protection, if the
	 * maximal protection is desired, there isn't any change
	 * to be made.
	 */
	if ((prot & (VM_PROT_READ|VM_PROT_WRITE)) ==
	    (VM_PROT_READ|VM_PROT_WRITE))
		return;

	pvo_head = vm_page_to_pvoh(m);
	for (pvo = LIST_FIRST(pvo_head); pvo != NULL; pvo = next_pvo) {
		next_pvo = LIST_NEXT(pvo, pvo_vlink);
		MOEA_PVO_CHECK(pvo);	/* sanity check */
		pmap = pvo->pvo_pmap;
		PMAP_LOCK(pmap);

		/*
		 * Downgrading to no mapping at all, we just remove the entry.
		 */
		if ((prot & VM_PROT_READ) == 0) {
			moea_pvo_remove(pvo, -1);
			PMAP_UNLOCK(pmap);
			continue;
		}

		/*
		 * If EXEC permission is being revoked, just clear the flag
		 * in the PVO.
		 */
		if ((prot & VM_PROT_EXECUTE) == 0)
			pvo->pvo_vaddr &= ~PVO_EXECUTABLE;

		/*
		 * If this entry is already RO, don't diddle with the page
		 * table.
		 */
		if ((pvo->pvo_pte.pte_lo & PTE_PP) == PTE_BR) {
			PMAP_UNLOCK(pmap);
			MOEA_PVO_CHECK(pvo);
			continue;
		}

		/*
		 * Grab the PTE before we diddle the bits so pvo_to_pte can
		 * verify the pte contents are as expected.
		 */
		pt = moea_pvo_to_pte(pvo, -1);
		pvo->pvo_pte.pte_lo &= ~PTE_PP;
		pvo->pvo_pte.pte_lo |= PTE_BR;
		if (pt != NULL)
			moea_pte_change(pt, &pvo->pvo_pte, pvo->pvo_vaddr);
		PMAP_UNLOCK(pmap);
		MOEA_PVO_CHECK(pvo);	/* sanity check */
	}

	/*
	 * Downgrading from writeable: clear the VM page flag
	 */
	if ((prot & VM_PROT_WRITE) != VM_PROT_WRITE)
		vm_page_flag_clear(m, PG_WRITEABLE);
}

/*
 * Returns true if the pmap's pv is one of the first
 * 16 pvs linked to from this page.  This count may
 * be changed upwards or downwards in the future; it
 * is only necessary that true be returned for a small
 * subset of pmaps for proper page aging.
 */
boolean_t
moea_page_exists_quick(mmu_t mmu, pmap_t pmap, vm_page_t m)
{
        int loops;
	struct pvo_entry *pvo;

        if (!moea_initialized || (m->flags & PG_FICTITIOUS))
                return FALSE;

	loops = 0;
	LIST_FOREACH(pvo, vm_page_to_pvoh(m), pvo_vlink) {
		if (pvo->pvo_pmap == pmap)
			return (TRUE);
		if (++loops >= 16)
			break;
	}

	return (FALSE);
}

static u_int	moea_vsidcontext;

void
moea_pinit(mmu_t mmu, pmap_t pmap)
{
	int	i, mask;
	u_int	entropy;

	KASSERT((int)pmap < VM_MIN_KERNEL_ADDRESS, ("moea_pinit: virt pmap"));
	PMAP_LOCK_INIT(pmap);

	entropy = 0;
	__asm __volatile("mftb %0" : "=r"(entropy));

	/*
	 * Allocate some segment registers for this pmap.
	 */
	for (i = 0; i < NPMAPS; i += VSID_NBPW) {
		u_int	hash, n;

		/*
		 * Create a new value by mutiplying by a prime and adding in
		 * entropy from the timebase register.  This is to make the
		 * VSID more random so that the PT hash function collides
		 * less often.  (Note that the prime casues gcc to do shifts
		 * instead of a multiply.)
		 */
		moea_vsidcontext = (moea_vsidcontext * 0x1105) + entropy;
		hash = moea_vsidcontext & (NPMAPS - 1);
		if (hash == 0)		/* 0 is special, avoid it */
			continue;
		n = hash >> 5;
		mask = 1 << (hash & (VSID_NBPW - 1));
		hash = (moea_vsidcontext & 0xfffff);
		if (moea_vsid_bitmap[n] & mask) {	/* collision? */
			/* anything free in this bucket? */
			if (moea_vsid_bitmap[n] == 0xffffffff) {
				entropy = (moea_vsidcontext >> 20);
				continue;
			}
			i = ffs(~moea_vsid_bitmap[i]) - 1;
			mask = 1 << i;
			hash &= 0xfffff & ~(VSID_NBPW - 1);
			hash |= i;
		}
		moea_vsid_bitmap[n] |= mask;
		for (i = 0; i < 16; i++)
			pmap->pm_sr[i] = VSID_MAKE(i, hash);
		return;
	}

	panic("moea_pinit: out of segments");
}

/*
 * Initialize the pmap associated with process 0.
 */
void
moea_pinit0(mmu_t mmu, pmap_t pm)
{

	moea_pinit(mmu, pm);
	bzero(&pm->pm_stats, sizeof(pm->pm_stats));
}

/*
 * Set the physical protection on the specified range of this map as requested.
 */
void
moea_protect(mmu_t mmu, pmap_t pm, vm_offset_t sva, vm_offset_t eva,
    vm_prot_t prot)
{
	struct	pvo_entry *pvo;
	struct	pte *pt;
	int	pteidx;

	CTR4(KTR_PMAP, "moea_protect: pm=%p sva=%#x eva=%#x prot=%#x", pm, sva,
	    eva, prot);


	KASSERT(pm == &curproc->p_vmspace->vm_pmap || pm == kernel_pmap,
	    ("moea_protect: non current pmap"));

	if ((prot & VM_PROT_READ) == VM_PROT_NONE) {
		mtx_lock(&Giant);
		moea_remove(mmu, pm, sva, eva);
		mtx_unlock(&Giant);
		return;
	}

	mtx_lock(&Giant);
	vm_page_lock_queues();
	PMAP_LOCK(pm);
	for (; sva < eva; sva += PAGE_SIZE) {
		pvo = moea_pvo_find_va(pm, sva, &pteidx);
		if (pvo == NULL)
			continue;

		if ((prot & VM_PROT_EXECUTE) == 0)
			pvo->pvo_vaddr &= ~PVO_EXECUTABLE;

		/*
		 * Grab the PTE pointer before we diddle with the cached PTE
		 * copy.
		 */
		pt = moea_pvo_to_pte(pvo, pteidx);
		/*
		 * Change the protection of the page.
		 */
		pvo->pvo_pte.pte_lo &= ~PTE_PP;
		pvo->pvo_pte.pte_lo |= PTE_BR;

		/*
		 * If the PVO is in the page table, update that pte as well.
		 */
		if (pt != NULL)
			moea_pte_change(pt, &pvo->pvo_pte, pvo->pvo_vaddr);
	}
	vm_page_unlock_queues();
	PMAP_UNLOCK(pm);
	mtx_unlock(&Giant);
}

/*
 * Map a list of wired pages into kernel virtual address space.  This is
 * intended for temporary mappings which do not need page modification or
 * references recorded.  Existing mappings in the region are overwritten.
 */
void
moea_qenter(mmu_t mmu, vm_offset_t sva, vm_page_t *m, int count)
{
	vm_offset_t va;

	va = sva;
	while (count-- > 0) {
		moea_kenter(mmu, va, VM_PAGE_TO_PHYS(*m));
		va += PAGE_SIZE;
		m++;
	}
}

/*
 * Remove page mappings from kernel virtual address space.  Intended for
 * temporary mappings entered by moea_qenter.
 */
void
moea_qremove(mmu_t mmu, vm_offset_t sva, int count)
{
	vm_offset_t va;

	va = sva;
	while (count-- > 0) {
		moea_kremove(mmu, va);
		va += PAGE_SIZE;
	}
}

void
moea_release(mmu_t mmu, pmap_t pmap)
{
        int idx, mask;
        
	/*
	 * Free segment register's VSID
	 */
        if (pmap->pm_sr[0] == 0)
                panic("moea_release");

        idx = VSID_TO_HASH(pmap->pm_sr[0]) & (NPMAPS-1);
        mask = 1 << (idx % VSID_NBPW);
        idx /= VSID_NBPW;
        moea_vsid_bitmap[idx] &= ~mask;
	PMAP_LOCK_DESTROY(pmap);
}

/*
 * Remove the given range of addresses from the specified map.
 */
void
moea_remove(mmu_t mmu, pmap_t pm, vm_offset_t sva, vm_offset_t eva)
{
	struct	pvo_entry *pvo;
	int	pteidx;

	vm_page_lock_queues();
	PMAP_LOCK(pm);
	for (; sva < eva; sva += PAGE_SIZE) {
		pvo = moea_pvo_find_va(pm, sva, &pteidx);
		if (pvo != NULL) {
			moea_pvo_remove(pvo, pteidx);
		}
	}
	PMAP_UNLOCK(pm);
	vm_page_unlock_queues();
}

/*
 * Remove physical page from all pmaps in which it resides. moea_pvo_remove()
 * will reflect changes in pte's back to the vm_page.
 */
void
moea_remove_all(mmu_t mmu, vm_page_t m)
{
	struct  pvo_head *pvo_head;
	struct	pvo_entry *pvo, *next_pvo;
	pmap_t	pmap;

	mtx_assert(&vm_page_queue_mtx, MA_OWNED);

	pvo_head = vm_page_to_pvoh(m);
	for (pvo = LIST_FIRST(pvo_head); pvo != NULL; pvo = next_pvo) {
		next_pvo = LIST_NEXT(pvo, pvo_vlink);

		MOEA_PVO_CHECK(pvo);	/* sanity check */
		pmap = pvo->pvo_pmap;
		PMAP_LOCK(pmap);
		moea_pvo_remove(pvo, -1);
		PMAP_UNLOCK(pmap);
	}
	vm_page_flag_clear(m, PG_WRITEABLE);
}

/*
 * Allocate a physical page of memory directly from the phys_avail map.
 * Can only be called from moea_bootstrap before avail start and end are
 * calculated.
 */
static vm_offset_t
moea_bootstrap_alloc(vm_size_t size, u_int align)
{
	vm_offset_t	s, e;
	int		i, j;

	size = round_page(size);
	for (i = 0; phys_avail[i + 1] != 0; i += 2) {
		if (align != 0)
			s = (phys_avail[i] + align - 1) & ~(align - 1);
		else
			s = phys_avail[i];
		e = s + size;

		if (s < phys_avail[i] || e > phys_avail[i + 1])
			continue;

		if (s == phys_avail[i]) {
			phys_avail[i] += size;
		} else if (e == phys_avail[i + 1]) {
			phys_avail[i + 1] -= size;
		} else {
			for (j = phys_avail_count * 2; j > i; j -= 2) {
				phys_avail[j] = phys_avail[j - 2];
				phys_avail[j + 1] = phys_avail[j - 1];
			}

			phys_avail[i + 3] = phys_avail[i + 1];
			phys_avail[i + 1] = s;
			phys_avail[i + 2] = e;
			phys_avail_count++;
		}

		return (s);
	}
	panic("moea_bootstrap_alloc: could not allocate memory");
}

/*
 * Return an unmapped pvo for a kernel virtual address.
 * Used by pmap functions that operate on physical pages.
 */
static struct pvo_entry *
moea_rkva_alloc(mmu_t mmu)
{
	struct		pvo_entry *pvo;
	struct		pte *pt;
	vm_offset_t	kva;
	int		pteidx;

	if (moea_rkva_count == 0)
		panic("moea_rkva_alloc: no more reserved KVAs");

	kva = moea_rkva_start + (PAGE_SIZE * --moea_rkva_count);
	moea_kenter(mmu, kva, 0);

	pvo = moea_pvo_find_va(kernel_pmap, kva, &pteidx);

	if (pvo == NULL)
		panic("moea_kva_alloc: moea_pvo_find_va failed");

	pt = moea_pvo_to_pte(pvo, pteidx);

	if (pt == NULL)
		panic("moea_kva_alloc: moea_pvo_to_pte failed");

	moea_pte_unset(pt, &pvo->pvo_pte, pvo->pvo_vaddr);
	PVO_PTEGIDX_CLR(pvo);

	moea_pte_overflow++;

	return (pvo);
}

static void
moea_pa_map(struct pvo_entry *pvo, vm_offset_t pa, struct pte *saved_pt,
    int *depth_p)
{
	struct	pte *pt;

	/*
	 * If this pvo already has a valid pte, we need to save it so it can
	 * be restored later.  We then just reload the new PTE over the old
	 * slot.
	 */
	if (saved_pt != NULL) {
		pt = moea_pvo_to_pte(pvo, -1);

		if (pt != NULL) {
			moea_pte_unset(pt, &pvo->pvo_pte, pvo->pvo_vaddr);
			PVO_PTEGIDX_CLR(pvo);
			moea_pte_overflow++;
		}

		*saved_pt = pvo->pvo_pte;

		pvo->pvo_pte.pte_lo &= ~PTE_RPGN;
	}

	pvo->pvo_pte.pte_lo |= pa;

	if (!moea_pte_spill(pvo->pvo_vaddr))
		panic("moea_pa_map: could not spill pvo %p", pvo);

	if (depth_p != NULL)
		(*depth_p)++;
}

static void
moea_pa_unmap(struct pvo_entry *pvo, struct pte *saved_pt, int *depth_p)
{
	struct	pte *pt;

	pt = moea_pvo_to_pte(pvo, -1);

	if (pt != NULL) {
		moea_pte_unset(pt, &pvo->pvo_pte, pvo->pvo_vaddr);
		PVO_PTEGIDX_CLR(pvo);
		moea_pte_overflow++;
	}

	pvo->pvo_pte.pte_lo &= ~PTE_RPGN;

	/*
	 * If there is a saved PTE and it's valid, restore it and return.
	 */
	if (saved_pt != NULL && (saved_pt->pte_lo & PTE_RPGN) != 0) {
		if (depth_p != NULL && --(*depth_p) == 0)
			panic("moea_pa_unmap: restoring but depth == 0");

		pvo->pvo_pte = *saved_pt;

		if (!moea_pte_spill(pvo->pvo_vaddr))
			panic("moea_pa_unmap: could not spill pvo %p", pvo);
	}
}

static void
moea_syncicache(vm_offset_t pa, vm_size_t len)
{
	__syncicache((void *)pa, len);
}

static void
tlbia(void)
{
	caddr_t	i;

	SYNC();
	for (i = 0; i < (caddr_t)0x00040000; i += 0x00001000) {
		TLBIE(i);
		EIEIO();
	}
	TLBSYNC();
	SYNC();
}

static int
moea_pvo_enter(pmap_t pm, uma_zone_t zone, struct pvo_head *pvo_head,
    vm_offset_t va, vm_offset_t pa, u_int pte_lo, int flags)
{
	struct	pvo_entry *pvo;
	u_int	sr;
	int	first;
	u_int	ptegidx;
	int	i;
	int     bootstrap;

	moea_pvo_enter_calls++;
	first = 0;
	bootstrap = 0;

	/*
	 * Compute the PTE Group index.
	 */
	va &= ~ADDR_POFF;
	sr = va_to_sr(pm->pm_sr, va);
	ptegidx = va_to_pteg(sr, va);

	/*
	 * Remove any existing mapping for this page.  Reuse the pvo entry if
	 * there is a mapping.
	 */
	mtx_lock(&moea_table_mutex);
	LIST_FOREACH(pvo, &moea_pvo_table[ptegidx], pvo_olink) {
		if (pvo->pvo_pmap == pm && PVO_VADDR(pvo) == va) {
			if ((pvo->pvo_pte.pte_lo & PTE_RPGN) == pa &&
			    (pvo->pvo_pte.pte_lo & PTE_PP) ==
			    (pte_lo & PTE_PP)) {
				mtx_unlock(&moea_table_mutex);
				return (0);
			}
			moea_pvo_remove(pvo, -1);
			break;
		}
	}

	/*
	 * If we aren't overwriting a mapping, try to allocate.
	 */
	if (moea_initialized) {
		pvo = uma_zalloc(zone, M_NOWAIT);
	} else {
		if (moea_bpvo_pool_index >= BPVO_POOL_SIZE) {
			panic("moea_enter: bpvo pool exhausted, %d, %d, %d",
			      moea_bpvo_pool_index, BPVO_POOL_SIZE, 
			      BPVO_POOL_SIZE * sizeof(struct pvo_entry));
		}
		pvo = &moea_bpvo_pool[moea_bpvo_pool_index];
		moea_bpvo_pool_index++;
		bootstrap = 1;
	}

	if (pvo == NULL) {
		mtx_unlock(&moea_table_mutex);
		return (ENOMEM);
	}

	moea_pvo_entries++;
	pvo->pvo_vaddr = va;
	pvo->pvo_pmap = pm;
	LIST_INSERT_HEAD(&moea_pvo_table[ptegidx], pvo, pvo_olink);
	pvo->pvo_vaddr &= ~ADDR_POFF;
	if (flags & VM_PROT_EXECUTE)
		pvo->pvo_vaddr |= PVO_EXECUTABLE;
	if (flags & PVO_WIRED)
		pvo->pvo_vaddr |= PVO_WIRED;
	if (pvo_head != &moea_pvo_kunmanaged)
		pvo->pvo_vaddr |= PVO_MANAGED;
	if (bootstrap)
		pvo->pvo_vaddr |= PVO_BOOTSTRAP;
	if (flags & PVO_FAKE)
		pvo->pvo_vaddr |= PVO_FAKE;

	moea_pte_create(&pvo->pvo_pte, sr, va, pa | pte_lo);

	/*
	 * Remember if the list was empty and therefore will be the first
	 * item.
	 */
	if (LIST_FIRST(pvo_head) == NULL)
		first = 1;
	LIST_INSERT_HEAD(pvo_head, pvo, pvo_vlink);

	if (pvo->pvo_pte.pte_lo & PVO_WIRED)
		pm->pm_stats.wired_count++;
	pm->pm_stats.resident_count++;

	/*
	 * We hope this succeeds but it isn't required.
	 */
	i = moea_pte_insert(ptegidx, &pvo->pvo_pte);
	if (i >= 0) {
		PVO_PTEGIDX_SET(pvo, i);
	} else {
		panic("moea_pvo_enter: overflow");
		moea_pte_overflow++;
	}
	mtx_unlock(&moea_table_mutex);

	return (first ? ENOENT : 0);
}

static void
moea_pvo_remove(struct pvo_entry *pvo, int pteidx)
{
	struct	pte *pt;

	/*
	 * If there is an active pte entry, we need to deactivate it (and
	 * save the ref & cfg bits).
	 */
	pt = moea_pvo_to_pte(pvo, pteidx);
	if (pt != NULL) {
		moea_pte_unset(pt, &pvo->pvo_pte, pvo->pvo_vaddr);
		PVO_PTEGIDX_CLR(pvo);
	} else {
		moea_pte_overflow--;
	}

	/*
	 * Update our statistics.
	 */
	pvo->pvo_pmap->pm_stats.resident_count--;
	if (pvo->pvo_pte.pte_lo & PVO_WIRED)
		pvo->pvo_pmap->pm_stats.wired_count--;

	/*
	 * Save the REF/CHG bits into their cache if the page is managed.
	 */
	if ((pvo->pvo_vaddr & (PVO_MANAGED|PVO_FAKE)) == PVO_MANAGED) {
		struct	vm_page *pg;

		pg = PHYS_TO_VM_PAGE(pvo->pvo_pte.pte_lo & PTE_RPGN);
		if (pg != NULL) {
			moea_attr_save(pg, pvo->pvo_pte.pte_lo &
			    (PTE_REF | PTE_CHG));
		}
	}

	/*
	 * Remove this PVO from the PV list.
	 */
	LIST_REMOVE(pvo, pvo_vlink);

	/*
	 * Remove this from the overflow list and return it to the pool
	 * if we aren't going to reuse it.
	 */
	LIST_REMOVE(pvo, pvo_olink);
	if (!(pvo->pvo_vaddr & PVO_BOOTSTRAP))
		uma_zfree(pvo->pvo_vaddr & PVO_MANAGED ? moea_mpvo_zone :
		    moea_upvo_zone, pvo);
	moea_pvo_entries--;
	moea_pvo_remove_calls++;
}

static __inline int
moea_pvo_pte_index(const struct pvo_entry *pvo, int ptegidx)
{
	int	pteidx;

	/*
	 * We can find the actual pte entry without searching by grabbing
	 * the PTEG index from 3 unused bits in pte_lo[11:9] and by
	 * noticing the HID bit.
	 */
	pteidx = ptegidx * 8 + PVO_PTEGIDX_GET(pvo);
	if (pvo->pvo_pte.pte_hi & PTE_HID)
		pteidx ^= moea_pteg_mask * 8;

	return (pteidx);
}

static struct pvo_entry *
moea_pvo_find_va(pmap_t pm, vm_offset_t va, int *pteidx_p)
{
	struct	pvo_entry *pvo;
	int	ptegidx;
	u_int	sr;

	va &= ~ADDR_POFF;
	sr = va_to_sr(pm->pm_sr, va);
	ptegidx = va_to_pteg(sr, va);

	mtx_lock(&moea_table_mutex);
	LIST_FOREACH(pvo, &moea_pvo_table[ptegidx], pvo_olink) {
		if (pvo->pvo_pmap == pm && PVO_VADDR(pvo) == va) {
			if (pteidx_p)
				*pteidx_p = moea_pvo_pte_index(pvo, ptegidx);
			break;
		}
	}
	mtx_unlock(&moea_table_mutex);

	return (pvo);
}

static struct pte *
moea_pvo_to_pte(const struct pvo_entry *pvo, int pteidx)
{
	struct	pte *pt;

	/*
	 * If we haven't been supplied the ptegidx, calculate it.
	 */
	if (pteidx == -1) {
		int	ptegidx;
		u_int	sr;

		sr = va_to_sr(pvo->pvo_pmap->pm_sr, pvo->pvo_vaddr);
		ptegidx = va_to_pteg(sr, pvo->pvo_vaddr);
		pteidx = moea_pvo_pte_index(pvo, ptegidx);
	}

	pt = &moea_pteg_table[pteidx >> 3].pt[pteidx & 7];

	if ((pvo->pvo_pte.pte_hi & PTE_VALID) && !PVO_PTEGIDX_ISSET(pvo)) {
		panic("moea_pvo_to_pte: pvo %p has valid pte in pvo but no "
		    "valid pte index", pvo);
	}

	if ((pvo->pvo_pte.pte_hi & PTE_VALID) == 0 && PVO_PTEGIDX_ISSET(pvo)) {
		panic("moea_pvo_to_pte: pvo %p has valid pte index in pvo "
		    "pvo but no valid pte", pvo);
	}

	if ((pt->pte_hi ^ (pvo->pvo_pte.pte_hi & ~PTE_VALID)) == PTE_VALID) {
		if ((pvo->pvo_pte.pte_hi & PTE_VALID) == 0) {
			panic("moea_pvo_to_pte: pvo %p has valid pte in "
			    "moea_pteg_table %p but invalid in pvo", pvo, pt);
		}

		if (((pt->pte_lo ^ pvo->pvo_pte.pte_lo) & ~(PTE_CHG|PTE_REF))
		    != 0) {
			panic("moea_pvo_to_pte: pvo %p pte does not match "
			    "pte %p in moea_pteg_table", pvo, pt);
		}

		return (pt);
	}

	if (pvo->pvo_pte.pte_hi & PTE_VALID) {
		panic("moea_pvo_to_pte: pvo %p has invalid pte %p in "
		    "moea_pteg_table but valid in pvo", pvo, pt);
	}

	return (NULL);
}

/*
 * XXX: THIS STUFF SHOULD BE IN pte.c?
 */
int
moea_pte_spill(vm_offset_t addr)
{
	struct	pvo_entry *source_pvo, *victim_pvo;
	struct	pvo_entry *pvo;
	int	ptegidx, i, j;
	u_int	sr;
	struct	pteg *pteg;
	struct	pte *pt;

	moea_pte_spills++;

	sr = mfsrin(addr);
	ptegidx = va_to_pteg(sr, addr);

	/*
	 * Have to substitute some entry.  Use the primary hash for this.
	 * Use low bits of timebase as random generator.
	 */
	pteg = &moea_pteg_table[ptegidx];
	mtx_lock(&moea_table_mutex);
	__asm __volatile("mftb %0" : "=r"(i));
	i &= 7;
	pt = &pteg->pt[i];

	source_pvo = NULL;
	victim_pvo = NULL;
	LIST_FOREACH(pvo, &moea_pvo_table[ptegidx], pvo_olink) {
		/*
		 * We need to find a pvo entry for this address.
		 */
		MOEA_PVO_CHECK(pvo);
		if (source_pvo == NULL &&
		    moea_pte_match(&pvo->pvo_pte, sr, addr,
		    pvo->pvo_pte.pte_hi & PTE_HID)) {
			/*
			 * Now found an entry to be spilled into the pteg.
			 * The PTE is now valid, so we know it's active.
			 */
			j = moea_pte_insert(ptegidx, &pvo->pvo_pte);

			if (j >= 0) {
				PVO_PTEGIDX_SET(pvo, j);
				moea_pte_overflow--;
				MOEA_PVO_CHECK(pvo);
				mtx_unlock(&moea_table_mutex);
				return (1);
			}

			source_pvo = pvo;

			if (victim_pvo != NULL)
				break;
		}

		/*
		 * We also need the pvo entry of the victim we are replacing
		 * so save the R & C bits of the PTE.
		 */
		if ((pt->pte_hi & PTE_HID) == 0 && victim_pvo == NULL &&
		    moea_pte_compare(pt, &pvo->pvo_pte)) {
			victim_pvo = pvo;
			if (source_pvo != NULL)
				break;
		}
	}

	if (source_pvo == NULL) {
		mtx_unlock(&moea_table_mutex);
		return (0);
	}

	if (victim_pvo == NULL) {
		if ((pt->pte_hi & PTE_HID) == 0)
			panic("moea_pte_spill: victim p-pte (%p) has no pvo"
			    "entry", pt);

		/*
		 * If this is a secondary PTE, we need to search it's primary
		 * pvo bucket for the matching PVO.
		 */
		LIST_FOREACH(pvo, &moea_pvo_table[ptegidx ^ moea_pteg_mask],
		    pvo_olink) {
			MOEA_PVO_CHECK(pvo);
			/*
			 * We also need the pvo entry of the victim we are
			 * replacing so save the R & C bits of the PTE.
			 */
			if (moea_pte_compare(pt, &pvo->pvo_pte)) {
				victim_pvo = pvo;
				break;
			}
		}

		if (victim_pvo == NULL)
			panic("moea_pte_spill: victim s-pte (%p) has no pvo"
			    "entry", pt);
	}

	/*
	 * We are invalidating the TLB entry for the EA we are replacing even
	 * though it's valid.  If we don't, we lose any ref/chg bit changes
	 * contained in the TLB entry.
	 */
	source_pvo->pvo_pte.pte_hi &= ~PTE_HID;

	moea_pte_unset(pt, &victim_pvo->pvo_pte, victim_pvo->pvo_vaddr);
	moea_pte_set(pt, &source_pvo->pvo_pte);

	PVO_PTEGIDX_CLR(victim_pvo);
	PVO_PTEGIDX_SET(source_pvo, i);
	moea_pte_replacements++;

	MOEA_PVO_CHECK(victim_pvo);
	MOEA_PVO_CHECK(source_pvo);

	mtx_unlock(&moea_table_mutex);
	return (1);
}

static int
moea_pte_insert(u_int ptegidx, struct pte *pvo_pt)
{
	struct	pte *pt;
	int	i;

	/*
	 * First try primary hash.
	 */
	for (pt = moea_pteg_table[ptegidx].pt, i = 0; i < 8; i++, pt++) {
		if ((pt->pte_hi & PTE_VALID) == 0) {
			pvo_pt->pte_hi &= ~PTE_HID;
			moea_pte_set(pt, pvo_pt);
			return (i);
		}
	}

	/*
	 * Now try secondary hash.
	 */
	ptegidx ^= moea_pteg_mask;
	ptegidx++;
	for (pt = moea_pteg_table[ptegidx].pt, i = 0; i < 8; i++, pt++) {
		if ((pt->pte_hi & PTE_VALID) == 0) {
			pvo_pt->pte_hi |= PTE_HID;
			moea_pte_set(pt, pvo_pt);
			return (i);
		}
	}

	panic("moea_pte_insert: overflow");
	return (-1);
}

static boolean_t
moea_query_bit(vm_page_t m, int ptebit)
{
	struct	pvo_entry *pvo;
	struct	pte *pt;

#if 0
	if (moea_attr_fetch(m) & ptebit)
		return (TRUE);
#endif

	LIST_FOREACH(pvo, vm_page_to_pvoh(m), pvo_vlink) {
		MOEA_PVO_CHECK(pvo);	/* sanity check */

		/*
		 * See if we saved the bit off.  If so, cache it and return
		 * success.
		 */
		if (pvo->pvo_pte.pte_lo & ptebit) {
			moea_attr_save(m, ptebit);
			MOEA_PVO_CHECK(pvo);	/* sanity check */
			return (TRUE);
		}
	}

	/*
	 * No luck, now go through the hard part of looking at the PTEs
	 * themselves.  Sync so that any pending REF/CHG bits are flushed to
	 * the PTEs.
	 */
	SYNC();
	LIST_FOREACH(pvo, vm_page_to_pvoh(m), pvo_vlink) {
		MOEA_PVO_CHECK(pvo);	/* sanity check */

		/*
		 * See if this pvo has a valid PTE.  if so, fetch the
		 * REF/CHG bits from the valid PTE.  If the appropriate
		 * ptebit is set, cache it and return success.
		 */
		pt = moea_pvo_to_pte(pvo, -1);
		if (pt != NULL) {
			moea_pte_synch(pt, &pvo->pvo_pte);
			if (pvo->pvo_pte.pte_lo & ptebit) {
				moea_attr_save(m, ptebit);
				MOEA_PVO_CHECK(pvo);	/* sanity check */
				return (TRUE);
			}
		}
	}

	return (FALSE);
}

static u_int
moea_clear_bit(vm_page_t m, int ptebit, int *origbit)
{
	u_int	count;
	struct	pvo_entry *pvo;
	struct	pte *pt;
	int	rv;

	/*
	 * Clear the cached value.
	 */
	rv = moea_attr_fetch(m);
	moea_attr_clear(m, ptebit);

	/*
	 * Sync so that any pending REF/CHG bits are flushed to the PTEs (so
	 * we can reset the right ones).  note that since the pvo entries and
	 * list heads are accessed via BAT0 and are never placed in the page
	 * table, we don't have to worry about further accesses setting the
	 * REF/CHG bits.
	 */
	SYNC();

	/*
	 * For each pvo entry, clear the pvo's ptebit.  If this pvo has a
	 * valid pte clear the ptebit from the valid pte.
	 */
	count = 0;
	LIST_FOREACH(pvo, vm_page_to_pvoh(m), pvo_vlink) {
		MOEA_PVO_CHECK(pvo);	/* sanity check */
		pt = moea_pvo_to_pte(pvo, -1);
		if (pt != NULL) {
			moea_pte_synch(pt, &pvo->pvo_pte);
			if (pvo->pvo_pte.pte_lo & ptebit) {
				count++;
				moea_pte_clear(pt, PVO_VADDR(pvo), ptebit);
			}
		}
		rv |= pvo->pvo_pte.pte_lo;
		pvo->pvo_pte.pte_lo &= ~ptebit;
		MOEA_PVO_CHECK(pvo);	/* sanity check */
	}

	if (origbit != NULL) {
		*origbit = rv;
	}

	return (count);
}

/*
 * Return true if the physical range is encompassed by the battable[idx]
 */
static int
moea_bat_mapped(int idx, vm_offset_t pa, vm_size_t size)
{
	u_int prot;
	u_int32_t start;
	u_int32_t end;
	u_int32_t bat_ble;

	/*
	 * Return immediately if not a valid mapping
	 */
	if (!battable[idx].batu & BAT_Vs)
		return (EINVAL);

	/*
	 * The BAT entry must be cache-inhibited, guarded, and r/w
	 * so it can function as an i/o page
	 */
	prot = battable[idx].batl & (BAT_I|BAT_G|BAT_PP_RW);
	if (prot != (BAT_I|BAT_G|BAT_PP_RW))
		return (EPERM);	

	/*
	 * The address should be within the BAT range. Assume that the
	 * start address in the BAT has the correct alignment (thus
	 * not requiring masking)
	 */
	start = battable[idx].batl & BAT_PBS;
	bat_ble = (battable[idx].batu & ~(BAT_EBS)) | 0x03;
	end = start | (bat_ble << 15) | 0x7fff;

	if ((pa < start) || ((pa + size) > end))
		return (ERANGE);

	return (0);
}

boolean_t
moea_dev_direct_mapped(mmu_t mmu, vm_offset_t pa, vm_size_t size)
{
	int i;

	/*
	 * This currently does not work for entries that 
	 * overlap 256M BAT segments.
	 */

	for(i = 0; i < 16; i++)
		if (moea_bat_mapped(i, pa, size) == 0)
			return (0);

	return (EFAULT);
}

/*
 * Map a set of physical memory pages into the kernel virtual
 * address space. Return a pointer to where it is mapped. This
 * routine is intended to be used for mapping device memory,
 * NOT real memory.
 */
void *
moea_mapdev(mmu_t mmu, vm_offset_t pa, vm_size_t size)
{
	vm_offset_t va, tmpva, ppa, offset;
	int i;

	ppa = trunc_page(pa);
	offset = pa & PAGE_MASK;
	size = roundup(offset + size, PAGE_SIZE);
	
	GIANT_REQUIRED;

	/*
	 * If the physical address lies within a valid BAT table entry,
	 * return the 1:1 mapping. This currently doesn't work
	 * for regions that overlap 256M BAT segments.
	 */
	for (i = 0; i < 16; i++) {
		if (moea_bat_mapped(i, pa, size) == 0)
			return ((void *) pa);
	}

	va = kmem_alloc_nofault(kernel_map, size);
	if (!va)
		panic("moea_mapdev: Couldn't alloc kernel virtual memory");

	for (tmpva = va; size > 0;) {
		moea_kenter(mmu, tmpva, ppa);
		TLBIE(tmpva); /* XXX or should it be invalidate-all ? */
		size -= PAGE_SIZE;
		tmpva += PAGE_SIZE;
		ppa += PAGE_SIZE;
	}

	return ((void *)(va + offset));
}

void
moea_unmapdev(mmu_t mmu, vm_offset_t va, vm_size_t size)
{
	vm_offset_t base, offset;

	/*
	 * If this is outside kernel virtual space, then it's a
	 * battable entry and doesn't require unmapping
	 */
	if ((va >= VM_MIN_KERNEL_ADDRESS) && (va <= VM_MAX_KERNEL_ADDRESS)) {
		base = trunc_page(va);
		offset = va & PAGE_MASK;
		size = roundup(offset + size, PAGE_SIZE);
		kmem_free(kernel_map, base, size);
	}
}
