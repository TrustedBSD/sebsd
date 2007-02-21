#-
# Copyright (c) 2005 Peter Grehan
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD: src/sys/powerpc/powerpc/mmu_if.m,v 1.2 2005/11/20 06:09:49 alc Exp $
#

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_page.h>

#include <machine/mmuvar.h>

/**
 * @defgroup MMU mmu - KObj methods for PowerPC MMU implementations
 * @brief A set of methods required by all MMU implementations. These
 * are basically direct call-thru's from the pmap machine-dependent
 * code.
 * Thanks to Bruce M Simpson's pmap man pages for routine descriptions.
 *@{
 */

INTERFACE mmu;

#
# Default implementations of some methods
#
CODE {
	static void mmu_null_copy(mmu_t mmu, pmap_t dst_pmap, pmap_t src_pmap,
	    vm_offset_t dst_addr, vm_size_t len, vm_offset_t src_addr)
	{
		return;
	}

	static void mmu_null_growkernel(mmu_t mmu, vm_offset_t addr)
	{
		return;
	}

	static void mmu_null_init(mmu_t mmu)
	{
		return;
	}

	static boolean_t mmu_null_is_prefaultable(mmu_t mmu, pmap_t pmap,
	    vm_offset_t va)
	{
		return (FALSE);
	}

	static void mmu_null_object_init_pt(mmu_t mmu, pmap_t pmap,
	    vm_offset_t addr, vm_object_t object, vm_pindex_t index,
	    vm_size_t size)
	{
		return;
	}

	static void mmu_null_page_init(mmu_t mmu, vm_page_t m)
	{
		return;
	}

	static void mmu_null_remove_pages(mmu_t mmu, pmap_t pmap,
	    vm_offset_t start, vm_offset_t end)
	{
		return;
	}

	static int mmu_null_mincore(mmu_t mmu, pmap_t pmap, vm_offset_t addr)
	{
		return (0);
	}

	static void mmu_null_deactivate(struct thread *td)
	{
		return;
	}

	static vm_offset_t mmu_null_addr_hint(mmu_t mmu, vm_object_t object,
	    vm_offset_t va, vm_size_t size)
	{
		return (va);
	}
};


/**
 * @brief Change the wiring attribute for the page in the given physical
 * map and virtual address.
 *
 * @param _pmap		physical map of page
 * @param _va		page virtual address
 * @param _wired	TRUE to increment wired count, FALSE to decrement
 */
METHOD void change_wiring {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_va;
	boolean_t	_wired;
};


/**
 * @brief Clear the 'modified' bit on the given physical page
 *
 * @param _pg		physical page
 */
METHOD void clear_modify {
	mmu_t		_mmu;
	vm_page_t	_pg;
};


/**
 * @brief Clear the 'referenced' bit on the given physical page
 *
 * @param _pg		physical page
 */
METHOD void clear_reference {
	mmu_t		_mmu;
	vm_page_t	_pg;
};


/**
 * @brief Copy the address range given by the source physical map, virtual
 * address and length to the destination physical map and virtual address.
 * This routine is optional (xxx default null implementation ?)
 *
 * @param _dst_pmap	destination physical map
 * @param _src_pmap	source physical map
 * @param _dst_addr	destination virtual address
 * @param _len		size of range
 * @param _src_addr	source virtual address
 */
METHOD void copy {
	mmu_t		_mmu;
	pmap_t		_dst_pmap;
	pmap_t		_src_pmap;
	vm_offset_t	_dst_addr;
	vm_size_t	_len;
	vm_offset_t	_src_addr;
} DEFAULT mmu_null_copy;


/**
 * @brief Copy the source physical page to the destination physical page
 *
 * @param _src		source physical page
 * @param _dst		destination physical page
 */
METHOD void copy_page {
	mmu_t		_mmu;
	vm_page_t	_src;
	vm_page_t	_dst;
};


/**
 * @brief Create a mapping between a virtual/physical address pair in the
 * passed physical map with the specified protection and wiring
 *
 * @param _pmap		physical map
 * @param _va		mapping virtual address
 * @param _p		mapping physical page
 * @param _prot		mapping page protection
 * @param _wired	TRUE if page will be wired
 */
METHOD void enter {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_va;
	vm_page_t	_p;
	vm_prot_t	_prot;
	boolean_t	_wired;
};


/**
 * @brief A faster entry point for page mapping where it is possible
 * to short-circuit some of the tests in pmap_enter.
 *
 * @param _pmap		physical map (and also currently active pmap)
 * @param _va		mapping virtual address
 * @param _pg		mapping physical page
 * @param _prot		new page protection - used to see if page is exec.
 * @param _mpte		???
 *
 * @retval NULL		(possibly a hint for future calls ?)
 */
METHOD vm_page_t enter_quick {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_va;
	vm_page_t	_pg;
	vm_prot_t	_prot;
	vm_page_t	_mpte;
};


/**
 * @brief Reverse map the given virtual address, returning the physical
 * page associated with the address if a mapping exists.
 *
 * @param _pmap		physical map
 * @param _va		mapping virtual address
 *
 * @retval 0		No mapping found
 * @retval addr		The mapping physical address
 */
METHOD vm_paddr_t extract {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_va;
};


/**
 * @brief Reverse map the given virtual address, returning the
 * physical page if found. The page must be held (by calling
 * vm_page_hold) if the page protection matches the given protection
 *
 * @param _pmap		physical map
 * @param _va		mapping virtual address
 * @param _prot		protection used to determine if physical page
 *			should be locked
 *
 * @retval NULL		No mapping found
 * @retval page		Pointer to physical page. Held if protections match
 */
METHOD vm_page_t extract_and_hold {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_va;
	vm_prot_t	_prot;
};


/**
 * @brief Increase kernel virtual address space to the given virtual address.
 * Not really required for PowerPC, so optional unless the MMU implementation
 * can use it.
 *
 * @param _va		new upper limit for kernel virtual address space
 */
METHOD void growkernel {
	mmu_t		_mmu;
	vm_offset_t	_va;
} DEFAULT mmu_null_growkernel;


/**
 * @brief Called from vm_mem_init. Zone allocation is available at
 * this stage so a convenient time to create zones. This routine is
 * for MMU-implementation convenience and is optional.
 */
METHOD void init {
	mmu_t		_mmu;
} DEFAULT mmu_null_init;


/**
 * @brief Return if the page has been marked by MMU hardware to have been
 * modified
 *
 * @param _pg		physical page to test
 *
 * @retval boolean	TRUE if page has been modified
 */
METHOD boolean_t is_modified {
	mmu_t		_mmu;
	vm_page_t	_pg;
};


/**
 * @brief Return whether the specified virtual address is a candidate to be
 * prefaulted in. This routine is optional.
 *
 * @param _pmap		physical map
 * @param _va		virtual address to test
 *
 * @retval boolean	TRUE if the address is a candidate.
 */
METHOD boolean_t is_prefaultable {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_va;
} DEFAULT mmu_null_is_prefaultable;


/**
 * @brief Return a count of referenced bits for a page, clearing those bits.
 * Not all referenced bits need to be cleared, but it is necessary that 0
 * only be returned when there are none set.
 *
 * @params _m		physical page
 *
 * @retval int		count of referenced bits
 */
METHOD boolean_t ts_referenced {
	mmu_t		_mmu;
	vm_page_t	_pg;
};


/**
 * @brief Map the requested physical address range into kernel virtual
 * address space. The value in _virt is taken as a hint. The virtual
 * address of the range is returned, or NULL if the mapping could not
 * be created. The range can be direct-mapped if that is supported.
 *
 * @param *_virt	Hint for start virtual address, and also return
 *			value
 * @param _start	physical address range start
 * @param _end		physical address range end
 * @param _prot		protection of range (currently ignored)
 *
 * @retval NULL		could not map the area
 * @retval addr, *_virt	mapping start virtual address
 */
METHOD vm_offset_t map {
	mmu_t		_mmu;
	vm_offset_t	*_virt;
	vm_paddr_t	_start;
	vm_paddr_t	_end;
	int		_prot;
};


/**
 * @brief Used to create a contiguous set of read-only mappings for a
 * given object to try and eliminate a cascade of on-demand faults as
 * the object is accessed sequentially. This routine is optional.
 *
 * @param _pmap		physical map
 * @param _addr		mapping start virtual address
 * @param _object	device-backed V.M. object to be mapped
 * @param _pindex	page-index within object of mapping start
 * @param _size		size in bytes of mapping
 */
METHOD void object_init_pt {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_addr;
	vm_object_t	_object;
	vm_pindex_t	_pindex;
	vm_size_t	_size;
} DEFAULT mmu_null_object_init_pt;


/**
 * @brief Used to determine if the specified page has a mapping for the
 * given physical map, by scanning the list of reverse-mappings from the
 * page. The list is scanned to a maximum of 16 entries.
 *
 * @param _pmap		physical map
 * @param _pg		physical page
 *
 * @retval bool		TRUE if the physical map was found in the first 16
 *			reverse-map list entries off the physical page.
 */
METHOD boolean_t page_exists_quick {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_page_t	_pg;
};


/**
 * @brief Initialise the machine-dependent section of the physical page
 * data structure. This routine is optional.
 *
 * @param _pg		physical page
 */
METHOD void page_init {
	mmu_t		_mmu;
	vm_page_t	_pg;
} DEFAULT mmu_null_page_init;


/**
 * @brief Lower the protection to the given value for all mappings of the
 * given physical page.
 *
 * @param _pg		physical page
 * @param _prot		updated page protection
 */
METHOD void page_protect {
	mmu_t		_mmu;
	vm_page_t	_pg;
	vm_prot_t	_prot;
};


/**
 * @brief Initialise a physical map data structure
 *
 * @param _pmap		physical map
 */
METHOD void pinit {
	mmu_t		_mmu;
	pmap_t		_pmap;
};


/**
 * @brief Initialise the physical map for process 0, the initial process
 * in the system.
 * XXX default to pinit ?
 *
 * @param _pmap		physical map
 */
METHOD void pinit0 {
	mmu_t		_mmu;
	pmap_t		_pmap;
};


/**
 * @brief Set the protection for physical pages in the given virtual address
 * range to the given value.
 *
 * @param _pmap		physical map
 * @param _start	virtual range start
 * @param _end		virtual range end
 * @param _prot		new page protection
 */
METHOD void protect {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_start;
	vm_offset_t	_end;
	vm_prot_t	_prot;
};


/**
 * @brief Create a mapping in kernel virtual address space for the given array
 * of wired physical pages.
 *
 * @param _start	mapping virtual address start
 * @param *_m		array of physical page pointers
 * @param _count	array elements
 */
METHOD void qenter {
	mmu_t		_mmu;
	vm_offset_t	_start;
	vm_page_t	*_pg;
	int		_count;
};


/**
 * @brief Remove the temporary mappings created by qenter.
 *
 * @param _start	mapping virtual address start
 * @param _count	number of pages in mapping
 */
METHOD void qremove {
	mmu_t		_mmu;
	vm_offset_t	_start;
	int		_count;
};


/**
 * @brief Release per-pmap resources, e.g. mutexes, allocated memory etc. There
 * should be no existing mappings for the physical map at this point
 *
 * @param _pmap		physical map
 */
METHOD void release {
	mmu_t		_mmu;
	pmap_t		_pmap;
};


/**
 * @brief Remove all mappings in the given physical map for the start/end
 * virtual address range. The range will be page-aligned.
 *
 * @param _pmap		physical map
 * @param _start	mapping virtual address start
 * @param _end		mapping virtual address end
 */
METHOD void remove {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_start;
	vm_offset_t	_end;
};


/**
 * @brief Traverse the reverse-map list off the given physical page and
 * remove all mappings. Clear the PG_WRITEABLE attribute from the page.
 *
 * @param _pg		physical page
 */
METHOD void remove_all {
	mmu_t		_mmu;
	vm_page_t	_pg;
};


/**
 * @brief Remove all mappings in the given start/end virtual address range
 * for the given physical map. Similar to the remove method, but it used
 * when tearing down all mappings in an address space. This method is
 * optional, since pmap_remove will be called for each valid vm_map in
 * the address space later.
 *
 * @param _pmap		physical map
 * @param _start	mapping virtual address start
 * @param _end		mapping virtual address end
 */
METHOD void remove_pages {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_start;
	vm_offset_t	_end;
} DEFAULT mmu_null_remove_pages;


/**
 * @brief Zero a physical page. It is not assumed that the page is mapped,
 * so a temporary (or direct) mapping may need to be used.
 *
 * @param _pg		physical page
 */
METHOD void zero_page {
	mmu_t		_mmu;
	vm_page_t	_pg;
};


/**
 * @brief Zero a portion of a physical page, starting at a given offset and
 * for a given size (multiples of 512 bytes for 4k pages).
 *
 * @param _pg		physical page
 * @param _off		byte offset from start of page
 * @param _size		size of area to zero
 */
METHOD void zero_page_area {
	mmu_t		_mmu;
	vm_page_t	_pg;
	int		_off;
	int		_size;
};


/**
 * @brief Called from the idle loop to zero pages. XXX I think locking
 * constraints might be different here compared to zero_page.
 *
 * @param _pg		physical page
 */
METHOD void zero_page_idle {
	mmu_t		_mmu;
	vm_page_t	_pg;
};


/**
 * @brief Extract mincore(2) information from a mapping. This routine is
 * optional and is an optimisation: the mincore code will call is_modified
 * and ts_referenced if no result is returned.
 *
 * @param _pmap		physical map
 * @param _addr		page virtual address
 *
 * @retval 0		no result
 * @retval non-zero	mincore(2) flag values
 */
METHOD int mincore {
	mmu_t		_mmu;
	pmap_t		_pmap;
	vm_offset_t	_addr;
} DEFAULT mmu_null_mincore;


/**
 * @brief Perform any operations required to allow a physical map to be used
 * before it's address space is accessed.
 *
 * @param _td		thread associated with physical map
 */
METHOD void activate {
	mmu_t		_mmu;
	struct thread	*_td;
};

/**
 * @brief Perform any operations required to deactivate a physical map,
 * for instance as it is context-switched out.
 *
 * @param _td		thread associated with physical map
 */
METHOD void deactivate {
	mmu_t		_mmu;
	struct thread	*_td;
} DEFAULT mmu_null_deactivate;

/**
 * @brief Return a hint for the best virtual address to map a tentative
 * virtual address range in a given VM object. The default is to just
 * return the given tentative start address.
 *
 * @param _obj		VM backing object
 * @param _addr		initial guess at virtual address
 * @param _size		size of virtual address range
 */
METHOD vm_offset_t addr_hint {
	mmu_t		_mmu;
	vm_object_t	_obj;
	vm_offset_t	_addr;
	vm_size_t	_size;
} DEFAULT mmu_null_addr_hint;




/**
 * INTERNAL INTERFACES
 */

/**
 * @brief Bootstrap the VM system. At the completion of this routine, the
 * kernel will be running in it's own address space with full control over
 * paging.
 *
 * @param _start	start of reserved memory (obsolete ???)
 * @param _end		end of reserved memory (obsolete ???)
 *			XXX I think the intent of these was to allow
 *			the memory used by kernel text+data+bss and
 *			loader variables/load-time kld's to be carved out
 *			of available physical mem.
 *
 */
METHOD void bootstrap {
	mmu_t		_mmu;
	vm_offset_t	_start;
	vm_offset_t	_end;
};


/**
 * @brief Create a kernel mapping for a given physical address range.
 * Called by bus code on behalf of device drivers. The mapping does not
 * have to be a virtual address: it can be a direct-mapped physical address
 * if that is supported by the MMU.
 *
 * @param _pa		start physical address
 * @param _size		size in bytes of mapping
 *
 * @retval addr		address of mapping.
 */
METHOD void * mapdev {
	mmu_t		_mmu;
	vm_offset_t	_pa;
	vm_size_t	_size;
};


/**
 * @brief Remove the mapping created by mapdev. Called when a driver
 * is unloaded.
 *
 * @param _va		Mapping address returned from mapdev
 * @param _size		size in bytes of mapping
 */
METHOD void unmapdev {
	mmu_t		_mmu;
	vm_offset_t	_va;
	vm_size_t	_size;
};


/**
 * @brief Reverse-map a kernel virtual address
 *
 * @param _va		kernel virtual address to reverse-map
 *
 * @retval pa		physical address corresponding to mapping
 */
METHOD vm_offset_t kextract {
	mmu_t		_mmu;
	vm_offset_t	_va;
};


/**
 * @brief Map a wired page into kernel virtual address space
 *
 * @param _va		mapping virtual address
 * @param _pa		mapping physical address
 */
METHOD void kenter {
	mmu_t		_mmu;
	vm_offset_t	_va;
	vm_offset_t	_pa;
};


/**
 * @brief Determine if the given physical address range has been direct-mapped.
 *
 * @param _pa		physical address start
 * @param _size		physical address range size
 *
 * @retval bool		TRUE if the range is direct-mapped.
 */
METHOD boolean_t dev_direct_mapped {
	mmu_t		_mmu;
	vm_offset_t	_pa;
	vm_size_t	_size;
};