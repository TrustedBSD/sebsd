/*-
 * Copyright (c) 2002 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/i386/i386/dump_machdep.c,v 1.11 2005/07/02 19:57:31 marcel Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cons.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/elf.h>
#include <machine/md_var.h>

CTASSERT(sizeof(struct kerneldumpheader) == 512);

/*
 * Don't touch the first SIZEOF_METADATA bytes on the dump device. This
 * is to protect us from metadata and to protect metadata from us.
 */
#define	SIZEOF_METADATA		(64*1024)

#define	MD_ALIGN(x)	(((off_t)(x) + PAGE_MASK) & ~PAGE_MASK)
#define	DEV_ALIGN(x)	(((off_t)(x) + (DEV_BSIZE-1)) & ~(DEV_BSIZE-1))

struct md_pa {
	vm_paddr_t md_start;
	vm_paddr_t md_size;
};

typedef int callback_t(struct md_pa *, int, void *);

static struct kerneldumpheader kdh;
static off_t dumplo, fileofs;

/* Handle buffered writes. */
static char buffer[DEV_BSIZE];
static size_t fragsz;

/* 20 phys_avail entry pairs correspond to 10 md_pa's */
static struct md_pa dump_map[10];

static void
md_pa_init(void)
{
	int n, idx;

	bzero(dump_map, sizeof(dump_map));
	for (n = 0; n < sizeof(dump_map) / sizeof(dump_map[0]); n++) {
		idx = n * 2;
		if (dump_avail[idx] == 0 && dump_avail[idx + 1] == 0)
			break;
		dump_map[n].md_start = dump_avail[idx];
		dump_map[n].md_size = dump_avail[idx + 1] - dump_avail[idx];
	}
}

static struct md_pa *
md_pa_first(void)
{

	return (&dump_map[0]);
}

static struct md_pa *
md_pa_next(struct md_pa *mdp)
{

	mdp++;
	if (mdp->md_size == 0)
		mdp = NULL;
	return (mdp);
}

/* XXX should be MI */
static void
mkdumpheader(struct kerneldumpheader *kdh, uint32_t archver, uint64_t dumplen,
    uint32_t blksz)
{

	bzero(kdh, sizeof(*kdh));
	strncpy(kdh->magic, KERNELDUMPMAGIC, sizeof(kdh->magic));
	strncpy(kdh->architecture, MACHINE_ARCH, sizeof(kdh->architecture));
	kdh->version = htod32(KERNELDUMPVERSION);
	kdh->architectureversion = htod32(archver);
	kdh->dumplength = htod64(dumplen);
	kdh->dumptime = htod64(time_second);
	kdh->blocksize = htod32(blksz);
	strncpy(kdh->hostname, hostname, sizeof(kdh->hostname));
	strncpy(kdh->versionstring, version, sizeof(kdh->versionstring));
	if (panicstr != NULL)
		strncpy(kdh->panicstring, panicstr, sizeof(kdh->panicstring));
	kdh->parity = kerneldump_parity(kdh);
}

static int
buf_write(struct dumperinfo *di, char *ptr, size_t sz)
{
	size_t len;
	int error;

	while (sz) {
		len = DEV_BSIZE - fragsz;
		if (len > sz)
			len = sz;
		bcopy(ptr, buffer + fragsz, len);
		fragsz += len;
		ptr += len;
		sz -= len;
		if (fragsz == DEV_BSIZE) {
			error = di->dumper(di->priv, buffer, 0, dumplo,
			    DEV_BSIZE);
			if (error)
				return error;
			dumplo += DEV_BSIZE;
			fragsz = 0;
		}
	}

	return (0);
}

static int
buf_flush(struct dumperinfo *di)
{
	int error;

	if (fragsz == 0)
		return (0);

	error = di->dumper(di->priv, buffer, 0, dumplo, DEV_BSIZE);
	dumplo += DEV_BSIZE;
	fragsz = 0;
	return (error);
}

#define PG2MB(pgs) ((pgs + (1 << 8) - 1) >> 8)

static int
cb_dumpdata(struct md_pa *mdp, int seqnr, void *arg)
{
	struct dumperinfo *di = (struct dumperinfo*)arg;
	vm_paddr_t a, pa;
	void *va;
	uint64_t pgs;
	size_t counter, sz, chunk;
	int i, c, error, twiddle;

	error = 0;	/* catch case in which chunk size is 0 */
	counter = 0;	/* Update twiddle every 16MB */
	twiddle = 0;
	va = 0;
	pgs = mdp->md_size / PAGE_SIZE;
	pa = mdp->md_start;

	printf("  chunk %d: %lldMB (%lld pages)", seqnr, PG2MB(pgs), pgs);

	while (pgs) {
		chunk = pgs;
		if (chunk > MAXDUMPPGS)
			chunk = MAXDUMPPGS;
		sz = chunk << PAGE_SHIFT;
		counter += sz;
		if (counter >> 24) {
			printf(" %lld", PG2MB(pgs));
			counter &= (1<<24) - 1;
		}
		for (i = 0; i < chunk; i++) {
			a = pa + i * PAGE_SIZE;
			va = pmap_kenter_temporary(trunc_page(a), i);
		}
		error = di->dumper(di->priv, va, 0, dumplo, sz);
		if (error)
			break;
		dumplo += sz;
		pgs -= chunk;
		pa += sz;

		/* Check for user abort. */
		c = cncheckc();
		if (c == 0x03)
			return (ECANCELED);
		if (c != -1)
			printf(" (CTRL-C to abort) ");
	}
	printf(" ... %s\n", (error) ? "fail" : "ok");
	return (error);
}

static int
cb_dumphdr(struct md_pa *mdp, int seqnr, void *arg)
{
	struct dumperinfo *di = (struct dumperinfo*)arg;
	Elf_Phdr phdr;
	uint64_t size;
	int error;

	size = mdp->md_size;
	bzero(&phdr, sizeof(phdr));
	phdr.p_type = PT_LOAD;
	phdr.p_flags = PF_R;			/* XXX */
	phdr.p_offset = fileofs;
	phdr.p_vaddr = mdp->md_start;
	phdr.p_paddr = mdp->md_start;
	phdr.p_filesz = size;
	phdr.p_memsz = size;
	phdr.p_align = PAGE_SIZE;

	error = buf_write(di, (char*)&phdr, sizeof(phdr));
	fileofs += phdr.p_filesz;
	return (error);
}

static int
cb_size(struct md_pa *mdp, int seqnr, void *arg)
{
	uint64_t *sz = (uint64_t*)arg;

	*sz += (uint64_t)mdp->md_size;
	return (0);
}

static int
foreach_chunk(callback_t cb, void *arg)
{
	struct md_pa *mdp;
	int error, seqnr;

	seqnr = 0;
	mdp = md_pa_first();
	while (mdp != NULL) {
		error = (*cb)(mdp, seqnr++, arg);
		if (error)
			return (-error);
		mdp = md_pa_next(mdp);
	}
	return (seqnr);
}

void
dumpsys(struct dumperinfo *di)
{
	Elf_Ehdr ehdr;
	uint64_t dumpsize;
	off_t hdrgap;
	size_t hdrsz;
	int error;

	bzero(&ehdr, sizeof(ehdr));
	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELF_CLASS;
#if BYTE_ORDER == LITTLE_ENDIAN
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#else
	ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#endif
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_STANDALONE;	/* XXX big picture? */
	ehdr.e_type = ET_CORE;
	ehdr.e_machine = EM_386;
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_flags = 0;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(Elf_Phdr);
	ehdr.e_shentsize = sizeof(Elf_Shdr);

	md_pa_init();

	/* Calculate dump size. */
	dumpsize = 0L;
	ehdr.e_phnum = foreach_chunk(cb_size, &dumpsize);
	hdrsz = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize;
	fileofs = MD_ALIGN(hdrsz);
	dumpsize += fileofs;
	hdrgap = fileofs - DEV_ALIGN(hdrsz);

	/* Determine dump offset on device. */
	if (di->mediasize < SIZEOF_METADATA + dumpsize + sizeof(kdh) * 2) {
		error = ENOSPC;
		goto fail;
	}
	dumplo = di->mediaoffset + di->mediasize - dumpsize;
	dumplo -= sizeof(kdh) * 2;

	mkdumpheader(&kdh, KERNELDUMP_I386_VERSION, dumpsize, di->blocksize);

	printf("Dumping %llu MB (%d chunks)\n", (long long)dumpsize >> 20,
	    ehdr.e_phnum);

	/* Dump leader */
	error = di->dumper(di->priv, &kdh, 0, dumplo, sizeof(kdh));
	if (error)
		goto fail;
	dumplo += sizeof(kdh);

	/* Dump ELF header */
	error = buf_write(di, (char*)&ehdr, sizeof(ehdr));
	if (error)
		goto fail;

	/* Dump program headers */
	error = foreach_chunk(cb_dumphdr, di);
	if (error < 0)
		goto fail;
	buf_flush(di);

	/*
	 * All headers are written using blocked I/O, so we know the
	 * current offset is (still) block aligned. Skip the alignement
	 * in the file to have the segment contents aligned at page
	 * boundary. We cannot use MD_ALIGN on dumplo, because we don't
	 * care and may very well be unaligned within the dump device.
	 */
	dumplo += hdrgap;

	/* Dump memory chunks (updates dumplo) */
	error = foreach_chunk(cb_dumpdata, di);
	if (error < 0)
		goto fail;

	/* Dump trailer */
	error = di->dumper(di->priv, &kdh, 0, dumplo, sizeof(kdh));
	if (error)
		goto fail;

	/* Signal completion, signoff and exit stage left. */
	di->dumper(di->priv, NULL, 0, 0, 0);
	printf("\nDump complete\n");
	return;

 fail:
	if (error < 0)
		error = -error;

	if (error == ECANCELED)
		printf("\nDump aborted\n");
	else if (error == ENOSPC)
		printf("\nDump failed. Partition too small.\n");
	else
		printf("\n** DUMP FAILED (ERROR %d) **\n", error);
}
