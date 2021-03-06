/*-
 * Copyright (c) 2002 Doug Rabson
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/compat/freebsd32/freebsd32_misc.c,v 1.53 2006/03/08 20:21:53 ups Exp $");

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/exec.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>
#include <sys/namei.h>
#include <sys/imgact.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/file.h>		/* Must come after sys/malloc.h */
#include <sys/mbuf.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/resourcevar.h>
#include <sys/selinfo.h>
#include <sys/eventvar.h>	/* Must come after sys/selinfo.h */
#include <sys/pipe.h>		/* Must come after sys/selinfo.h */
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/wait.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>

#include <machine/cpu.h>

#include <compat/freebsd32/freebsd32_util.h>
#include <compat/freebsd32/freebsd32.h>
#include <compat/freebsd32/freebsd32_proto.h>

CTASSERT(sizeof(struct timeval32) == 8);
CTASSERT(sizeof(struct timespec32) == 8);
CTASSERT(sizeof(struct statfs32) == 256);
CTASSERT(sizeof(struct rusage32) == 72);

int
freebsd32_wait4(struct thread *td, struct freebsd32_wait4_args *uap)
{
	int error, status;
	struct rusage32 ru32;
	struct rusage ru, *rup;

	if (uap->rusage != NULL)
		rup = &ru;
	else
		rup = NULL;
	error = kern_wait(td, uap->pid, &status, uap->options, rup);
	if (error)
		return (error);
	if (uap->status != NULL)
		error = copyout(&status, uap->status, sizeof(status));
	if (uap->rusage != NULL && error == 0) {
		TV_CP(ru, ru32, ru_utime);
		TV_CP(ru, ru32, ru_stime);
		CP(ru, ru32, ru_maxrss);
		CP(ru, ru32, ru_ixrss);
		CP(ru, ru32, ru_idrss);
		CP(ru, ru32, ru_isrss);
		CP(ru, ru32, ru_minflt);
		CP(ru, ru32, ru_majflt);
		CP(ru, ru32, ru_nswap);
		CP(ru, ru32, ru_inblock);
		CP(ru, ru32, ru_oublock);
		CP(ru, ru32, ru_msgsnd);
		CP(ru, ru32, ru_msgrcv);
		CP(ru, ru32, ru_nsignals);
		CP(ru, ru32, ru_nvcsw);
		CP(ru, ru32, ru_nivcsw);
		error = copyout(&ru32, uap->rusage, sizeof(ru32));
	}
	return (error);
}

#ifdef COMPAT_FREEBSD4
static void
copy_statfs(struct statfs *in, struct statfs32 *out)
{
	
	bzero(out, sizeof(*out));
	CP(*in, *out, f_bsize);
	CP(*in, *out, f_iosize);
	CP(*in, *out, f_blocks);
	CP(*in, *out, f_bfree);
	CP(*in, *out, f_bavail);
	CP(*in, *out, f_files);
	CP(*in, *out, f_ffree);
	CP(*in, *out, f_fsid);
	CP(*in, *out, f_owner);
	CP(*in, *out, f_type);
	CP(*in, *out, f_flags);
	CP(*in, *out, f_flags);
	CP(*in, *out, f_syncwrites);
	CP(*in, *out, f_asyncwrites);
	strlcpy(out->f_fstypename,
	      in->f_fstypename, MFSNAMELEN);
	strlcpy(out->f_mntonname,
	      in->f_mntonname, min(MNAMELEN, FREEBSD4_MNAMELEN));
	CP(*in, *out, f_syncreads);
	CP(*in, *out, f_asyncreads);
	strlcpy(out->f_mntfromname,
	      in->f_mntfromname, min(MNAMELEN, FREEBSD4_MNAMELEN));
}
#endif

#ifdef COMPAT_FREEBSD4
int
freebsd4_freebsd32_getfsstat(struct thread *td, struct freebsd4_freebsd32_getfsstat_args *uap)
{
	struct statfs *buf, *sp;
	struct statfs32 stat32;
	size_t count, size;
	int error;

	count = uap->bufsize / sizeof(struct statfs32);
	size = count * sizeof(struct statfs);
	error = kern_getfsstat(td, &buf, size, UIO_SYSSPACE, uap->flags);
	if (size > 0) {
		count = td->td_retval[0];
		sp = buf;
		while (count > 0 && error == 0) {
			copy_statfs(sp, &stat32);
			error = copyout(&stat32, uap->buf, sizeof(stat32));
			sp++;
			uap->buf++;
			count--;
		}
		free(buf, M_TEMP);
	}
	return (error);
}
#endif

struct sigaltstack32 {
	u_int32_t	ss_sp;
	u_int32_t	ss_size;
	int		ss_flags;
};

CTASSERT(sizeof(struct sigaltstack32) == 12);

int
freebsd32_sigaltstack(struct thread *td,
		      struct freebsd32_sigaltstack_args *uap)
{
	struct sigaltstack32 s32;
	struct sigaltstack ss, oss, *ssp;
	int error;

	if (uap->ss != NULL) {
		error = copyin(uap->ss, &s32, sizeof(s32));
		if (error)
			return (error);
		PTRIN_CP(s32, ss, ss_sp);
		CP(s32, ss, ss_size);
		CP(s32, ss, ss_flags);
		ssp = &ss;
	} else
		ssp = NULL;
	error = kern_sigaltstack(td, ssp, &oss);
	if (error == 0 && uap->oss != NULL) {
		PTROUT_CP(oss, s32, ss_sp);
		CP(oss, s32, ss_size);
		CP(oss, s32, ss_flags);
		error = copyout(&s32, uap->oss, sizeof(s32));
	}
	return (error);
}

/*
 * Custom version of exec_copyin_args() so that we can translate
 * the pointers.
 */
static int
freebsd32_exec_copyin_args(struct image_args *args, char *fname,
    enum uio_seg segflg, u_int32_t *argv, u_int32_t *envv)
{
	char *argp, *envp;
	u_int32_t *p32, arg;
	size_t length;
	int error;

	bzero(args, sizeof(*args));
	if (argv == NULL)
		return (EFAULT);

	/*
	 * Allocate temporary demand zeroed space for argument and
	 *	environment strings
	 */
	args->buf = (char *) kmem_alloc_wait(exec_map,
	    PATH_MAX + ARG_MAX + MAXSHELLCMDLEN);
	if (args->buf == NULL)
		return (ENOMEM);
	args->begin_argv = args->buf;
	args->endp = args->begin_argv;
	args->stringspace = ARG_MAX;

	args->fname = args->buf + ARG_MAX;

	/*
	 * Copy the file name.
	 */
	error = (segflg == UIO_SYSSPACE) ?
	    copystr(fname, args->fname, PATH_MAX, &length) :
	    copyinstr(fname, args->fname, PATH_MAX, &length);
	if (error != 0)
		goto err_exit;

	/*
	 * extract arguments first
	 */
	p32 = argv;
	for (;;) {
		error = copyin(p32++, &arg, sizeof(arg));
		if (error)
			goto err_exit;
		if (arg == 0)
			break;
		argp = PTRIN(arg);
		error = copyinstr(argp, args->endp, args->stringspace, &length);
		if (error) {
			if (error == ENAMETOOLONG)
				error = E2BIG;
			goto err_exit;
		}
		args->stringspace -= length;
		args->endp += length;
		args->argc++;
	}
			
	args->begin_envv = args->endp;

	/*
	 * extract environment strings
	 */
	if (envv) {
		p32 = envv;
		for (;;) {
			error = copyin(p32++, &arg, sizeof(arg));
			if (error)
				goto err_exit;
			if (arg == 0)
				break;
			envp = PTRIN(arg);
			error = copyinstr(envp, args->endp, args->stringspace,
			    &length);
			if (error) {
				if (error == ENAMETOOLONG)
					error = E2BIG;
				goto err_exit;
			}
			args->stringspace -= length;
			args->endp += length;
			args->envc++;
		}
	}

	return (0);

err_exit:
	kmem_free_wakeup(exec_map, (vm_offset_t)args->buf,
	    PATH_MAX + ARG_MAX + MAXSHELLCMDLEN);
	args->buf = NULL;
	return (error);
}

int
freebsd32_execve(struct thread *td, struct freebsd32_execve_args *uap)
{
	struct image_args eargs;
	int error;

	error = freebsd32_exec_copyin_args(&eargs, uap->fname, UIO_USERSPACE,
	    uap->argv, uap->envv);
	if (error == 0)
		error = kern_execve(td, &eargs, NULL);
	return (error);
}

#ifdef __ia64__
static int
freebsd32_mmap_partial(struct thread *td, vm_offset_t start, vm_offset_t end,
		       int prot, int fd, off_t pos)
{
	vm_map_t map;
	vm_map_entry_t entry;
	int rv;

	map = &td->td_proc->p_vmspace->vm_map;
	if (fd != -1)
		prot |= VM_PROT_WRITE;

	if (vm_map_lookup_entry(map, start, &entry)) {
		if ((entry->protection & prot) != prot) {
			rv = vm_map_protect(map,
					    trunc_page(start),
					    round_page(end),
					    entry->protection | prot,
					    FALSE);
			if (rv != KERN_SUCCESS)
				return (EINVAL);
		}
	} else {
		vm_offset_t addr = trunc_page(start);
		rv = vm_map_find(map, 0, 0,
				 &addr, PAGE_SIZE, FALSE, prot,
				 VM_PROT_ALL, 0);
		if (rv != KERN_SUCCESS)
			return (EINVAL);
	}

	if (fd != -1) {
		struct pread_args r;
		r.fd = fd;
		r.buf = (void *) start;
		r.nbyte = end - start;
		r.offset = pos;
		return (pread(td, &r));
	} else {
		while (start < end) {
			subyte((void *) start, 0);
			start++;
		}
		return (0);
	}
}
#endif

int
freebsd32_mmap(struct thread *td, struct freebsd32_mmap_args *uap)
{
	struct mmap_args ap;
	vm_offset_t addr = (vm_offset_t) uap->addr;
	vm_size_t len	 = uap->len;
	int prot	 = uap->prot;
	int flags	 = uap->flags;
	int fd		 = uap->fd;
	off_t pos	 = (uap->poslo
			    | ((off_t)uap->poshi << 32));
#ifdef __ia64__
	vm_size_t pageoff;
	int error;

	/*
	 * Attempt to handle page size hassles.
	 */
	pageoff = (pos & PAGE_MASK);
	if (flags & MAP_FIXED) {
		vm_offset_t start, end;
		start = addr;
		end = addr + len;

		mtx_lock(&Giant);
		if (start != trunc_page(start)) {
			error = freebsd32_mmap_partial(td, start,
						       round_page(start), prot,
						       fd, pos);
			if (fd != -1)
				pos += round_page(start) - start;
			start = round_page(start);
		}
		if (end != round_page(end)) {
			vm_offset_t t = trunc_page(end);
			error = freebsd32_mmap_partial(td, t, end,
						  prot, fd,
						  pos + t - start);
			end = trunc_page(end);
		}
		if (end > start && fd != -1 && (pos & PAGE_MASK)) {
			/*
			 * We can't map this region at all. The specified
			 * address doesn't have the same alignment as the file
			 * position. Fake the mapping by simply reading the
			 * entire region into memory. First we need to make
			 * sure the region exists.
			 */
			vm_map_t map;
			struct pread_args r;
			int rv;

			prot |= VM_PROT_WRITE;
			map = &td->td_proc->p_vmspace->vm_map;
			rv = vm_map_remove(map, start, end);
			if (rv != KERN_SUCCESS) {
				mtx_unlock(&Giant);
				return (EINVAL);
			}
			rv = vm_map_find(map, 0, 0,
					 &start, end - start, FALSE,
					 prot, VM_PROT_ALL, 0);
			mtx_unlock(&Giant);
			if (rv != KERN_SUCCESS)
				return (EINVAL);
			r.fd = fd;
			r.buf = (void *) start;
			r.nbyte = end - start;
			r.offset = pos;
			error = pread(td, &r);
			if (error)
				return (error);

			td->td_retval[0] = addr;
			return (0);
		}
		mtx_unlock(&Giant);
		if (end == start) {
			/*
			 * After dealing with the ragged ends, there
			 * might be none left.
			 */
			td->td_retval[0] = addr;
			return (0);
		}
		addr = start;
		len = end - start;
	}
#endif

	ap.addr = (void *) addr;
	ap.len = len;
	ap.prot = prot;
	ap.flags = flags;
	ap.fd = fd;
	ap.pos = pos;

	return (mmap(td, &ap));
}

struct itimerval32 {
	struct timeval32 it_interval;
	struct timeval32 it_value;
};

CTASSERT(sizeof(struct itimerval32) == 16);

int
freebsd32_setitimer(struct thread *td, struct freebsd32_setitimer_args *uap)
{
	struct itimerval itv, oitv, *itvp;	
	struct itimerval32 i32;
	int error;

	if (uap->itv != NULL) {
		error = copyin(uap->itv, &i32, sizeof(i32));
		if (error)
			return (error);
		TV_CP(i32, itv, it_interval);
		TV_CP(i32, itv, it_value);
		itvp = &itv;
	} else
		itvp = NULL;
	error = kern_setitimer(td, uap->which, itvp, &oitv);
	if (error || uap->oitv == NULL)
		return (error);
	TV_CP(oitv, i32, it_interval);
	TV_CP(oitv, i32, it_value);
	return (copyout(&i32, uap->oitv, sizeof(i32)));
}

int
freebsd32_getitimer(struct thread *td, struct freebsd32_getitimer_args *uap)
{
	struct itimerval itv;
	struct itimerval32 i32;
	int error;

	error = kern_getitimer(td, uap->which, &itv);
	if (error || uap->itv == NULL)
		return (error);
	TV_CP(itv, i32, it_interval);
	TV_CP(itv, i32, it_value);
	return (copyout(&i32, uap->itv, sizeof(i32)));
}

int
freebsd32_select(struct thread *td, struct freebsd32_select_args *uap)
{
	struct timeval32 tv32;
	struct timeval tv, *tvp;
	int error;

	if (uap->tv != NULL) {
		error = copyin(uap->tv, &tv32, sizeof(tv32));
		if (error)
			return (error);
		CP(tv32, tv, tv_sec);
		CP(tv32, tv, tv_usec);
		tvp = &tv;
	} else
		tvp = NULL;
	/*
	 * XXX big-endian needs to convert the fd_sets too.
	 * XXX Do pointers need PTRIN()?
	 */
	return (kern_select(td, uap->nd, uap->in, uap->ou, uap->ex, tvp));
}

struct kevent32 {
	u_int32_t	ident;		/* identifier for this event */
	short		filter;		/* filter for event */
	u_short		flags;
	u_int		fflags;
	int32_t		data;
	u_int32_t	udata;		/* opaque user data identifier */
};

CTASSERT(sizeof(struct kevent32) == 20);
static int freebsd32_kevent_copyout(void *arg, struct kevent *kevp, int count);
static int freebsd32_kevent_copyin(void *arg, struct kevent *kevp, int count);

/*
 * Copy 'count' items into the destination list pointed to by uap->eventlist.
 */
static int
freebsd32_kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct freebsd32_kevent_args *uap;
	struct kevent32	ks32[KQ_NEVENTS];
	int i, error = 0;

	KASSERT(count <= KQ_NEVENTS, ("count (%d) > KQ_NEVENTS", count));
	uap = (struct freebsd32_kevent_args *)arg;

	for (i = 0; i < count; i++) {
		CP(kevp[i], ks32[i], ident);
		CP(kevp[i], ks32[i], filter);
		CP(kevp[i], ks32[i], flags);
		CP(kevp[i], ks32[i], fflags);
		CP(kevp[i], ks32[i], data);
		PTROUT_CP(kevp[i], ks32[i], udata);
	}
	error = copyout(ks32, uap->eventlist, count * sizeof *ks32);
	if (error == 0)
		uap->eventlist += count;
	return (error);
}

/*
 * Copy 'count' items from the list pointed to by uap->changelist.
 */
static int
freebsd32_kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct freebsd32_kevent_args *uap;
	struct kevent32	ks32[KQ_NEVENTS];
	int i, error = 0;

	KASSERT(count <= KQ_NEVENTS, ("count (%d) > KQ_NEVENTS", count));
	uap = (struct freebsd32_kevent_args *)arg;

	error = copyin(uap->changelist, ks32, count * sizeof *ks32);
	if (error)
		goto done;
	uap->changelist += count;

	for (i = 0; i < count; i++) {
		CP(ks32[i], kevp[i], ident);
		CP(ks32[i], kevp[i], filter);
		CP(ks32[i], kevp[i], flags);
		CP(ks32[i], kevp[i], fflags);
		CP(ks32[i], kevp[i], data);
		PTRIN_CP(ks32[i], kevp[i], udata);
	}
done:
	return (error);
}

int
freebsd32_kevent(struct thread *td, struct freebsd32_kevent_args *uap)
{
	struct timespec32 ts32;
	struct timespec ts, *tsp;
	struct kevent_copyops k_ops = { uap,
					freebsd32_kevent_copyout,
					freebsd32_kevent_copyin};
	int error;


	if (uap->timeout) {
		error = copyin(uap->timeout, &ts32, sizeof(ts32));
		if (error)
			return (error);
		CP(ts32, ts, tv_sec);
		CP(ts32, ts, tv_nsec);
		tsp = &ts;
	} else
		tsp = NULL;
	error = kern_kevent(td, uap->fd, uap->nchanges, uap->nevents,
	    &k_ops, tsp);
	return (error);
}

int
freebsd32_gettimeofday(struct thread *td,
		       struct freebsd32_gettimeofday_args *uap)
{
	struct timeval atv;
	struct timeval32 atv32;
	struct timezone rtz;
	int error = 0;

	if (uap->tp) {
		microtime(&atv);
		CP(atv, atv32, tv_sec);
		CP(atv, atv32, tv_usec);
		error = copyout(&atv32, uap->tp, sizeof (atv32));
	}
	if (error == 0 && uap->tzp != NULL) {
		rtz.tz_minuteswest = tz_minuteswest;
		rtz.tz_dsttime = tz_dsttime;
		error = copyout(&rtz, uap->tzp, sizeof (rtz));
	}
	return (error);
}

int
freebsd32_getrusage(struct thread *td, struct freebsd32_getrusage_args *uap)
{
	struct rusage32 s32;
	struct rusage s;
	int error;

	error = kern_getrusage(td, uap->who, &s);
	if (error)
		return (error);
	if (uap->rusage != NULL) {
		TV_CP(s, s32, ru_utime);
		TV_CP(s, s32, ru_stime);
		CP(s, s32, ru_maxrss);
		CP(s, s32, ru_ixrss);
		CP(s, s32, ru_idrss);
		CP(s, s32, ru_isrss);
		CP(s, s32, ru_minflt);
		CP(s, s32, ru_majflt);
		CP(s, s32, ru_nswap);
		CP(s, s32, ru_inblock);
		CP(s, s32, ru_oublock);
		CP(s, s32, ru_msgsnd);
		CP(s, s32, ru_msgrcv);
		CP(s, s32, ru_nsignals);
		CP(s, s32, ru_nvcsw);
		CP(s, s32, ru_nivcsw);
		error = copyout(&s32, uap->rusage, sizeof(s32));
	}
	return (error);
}

struct iovec32 {
	u_int32_t iov_base;
	int	iov_len;
};

CTASSERT(sizeof(struct iovec32) == 8);

static int
freebsd32_copyinuio(struct iovec32 *iovp, u_int iovcnt, struct uio **uiop)
{
	struct iovec32 iov32;
	struct iovec *iov;
	struct uio *uio;
	u_int iovlen;
	int error, i;

	*uiop = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (EINVAL);
	iovlen = iovcnt * sizeof(struct iovec);
	uio = malloc(iovlen + sizeof *uio, M_IOV, M_WAITOK);
	iov = (struct iovec *)(uio + 1);
	for (i = 0; i < iovcnt; i++) {
		error = copyin(&iovp[i], &iov32, sizeof(struct iovec32));
		if (error) {
			free(uio, M_IOV);
			return (error);
		}
		iov[i].iov_base = PTRIN(iov32.iov_base);
		iov[i].iov_len = iov32.iov_len;
	}
	uio->uio_iov = iov;
	uio->uio_iovcnt = iovcnt;
	uio->uio_segflg = UIO_USERSPACE;
	uio->uio_offset = -1;
	uio->uio_resid = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov->iov_len > INT_MAX - uio->uio_resid) {
			free(uio, M_IOV);
			return (EINVAL);
		}
		uio->uio_resid += iov->iov_len;
		iov++;
	}
	*uiop = uio;
	return (0);
}

int
freebsd32_readv(struct thread *td, struct freebsd32_readv_args *uap)
{
	struct uio *auio;
	int error;

	error = freebsd32_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_readv(td, uap->fd, auio);
	free(auio, M_IOV);
	return (error);
}

int
freebsd32_writev(struct thread *td, struct freebsd32_writev_args *uap)
{
	struct uio *auio;
	int error;

	error = freebsd32_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_writev(td, uap->fd, auio);
	free(auio, M_IOV);
	return (error);
}

int
freebsd32_preadv(struct thread *td, struct freebsd32_preadv_args *uap)
{
	struct uio *auio;
	int error;

	error = freebsd32_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_preadv(td, uap->fd, auio, uap->offset);
	free(auio, M_IOV);
	return (error);
}

int
freebsd32_pwritev(struct thread *td, struct freebsd32_pwritev_args *uap)
{
	struct uio *auio;
	int error;

	error = freebsd32_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_pwritev(td, uap->fd, auio, uap->offset);
	free(auio, M_IOV);
	return (error);
}

static int
freebsd32_copyiniov(struct iovec32 *iovp32, u_int iovcnt, struct iovec **iovp,
    int error)
{
	struct iovec32 iov32;
	struct iovec *iov;
	u_int iovlen;
	int i;

	*iovp = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (error);
	iovlen = iovcnt * sizeof(struct iovec);
	iov = malloc(iovlen, M_IOV, M_WAITOK);
	for (i = 0; i < iovcnt; i++) {
		error = copyin(&iovp32[i], &iov32, sizeof(struct iovec32));
		if (error) {
			free(iov, M_IOV);
			return (error);
		}
		iov[i].iov_base = PTRIN(iov32.iov_base);
		iov[i].iov_len = iov32.iov_len;
	}
	*iovp = iov;
	return (0);
}

static int
freebsd32_copyoutiov(struct iovec *iov, u_int iovcnt, struct iovec32 *iovp,
    int error)
{
	struct iovec32 iov32;
	int i;

	if (iovcnt > UIO_MAXIOV)
		return (error);
	for (i = 0; i < iovcnt; i++) {
		iov32.iov_base = PTROUT(iov[i].iov_base);
		iov32.iov_len = iov[i].iov_len;
		error = copyout(&iov32, &iovp[i], sizeof(iov32));
		if (error)
			return (error);
	}
	return (0);
}


struct msghdr32 {
	u_int32_t	 msg_name;
	socklen_t	 msg_namelen;
	u_int32_t	 msg_iov;
	int		 msg_iovlen;
	u_int32_t	 msg_control;
	socklen_t	 msg_controllen;
	int		 msg_flags;
};
CTASSERT(sizeof(struct msghdr32) == 28);

static int
freebsd32_copyinmsghdr(struct msghdr32 *msg32, struct msghdr *msg)
{
	struct msghdr32 m32;
	int error;

	error = copyin(msg32, &m32, sizeof(m32));
	if (error)
		return (error);
	msg->msg_name = PTRIN(m32.msg_name);
	msg->msg_namelen = m32.msg_namelen;
	msg->msg_iov = PTRIN(m32.msg_iov);
	msg->msg_iovlen = m32.msg_iovlen;
	msg->msg_control = PTRIN(m32.msg_control);
	msg->msg_controllen = m32.msg_controllen;
	msg->msg_flags = m32.msg_flags;
	return (0);
}

static int
freebsd32_copyoutmsghdr(struct msghdr *msg, struct msghdr32 *msg32)
{
	struct msghdr32 m32;
	int error;

	m32.msg_name = PTROUT(msg->msg_name);
	m32.msg_namelen = msg->msg_namelen;
	m32.msg_iov = PTROUT(msg->msg_iov);
	m32.msg_iovlen = msg->msg_iovlen;
	m32.msg_control = PTROUT(msg->msg_control);
	m32.msg_controllen = msg->msg_controllen;
	m32.msg_flags = msg->msg_flags;
	error = copyout(&m32, msg32, sizeof(m32));
	return (error);
}

#define FREEBSD32_ALIGNBYTES	(sizeof(int) - 1)
#define FREEBSD32_ALIGN(p)	\
	(((u_long)(p) + FREEBSD32_ALIGNBYTES) & ~FREEBSD32_ALIGNBYTES)
#define	FREEBSD32_CMSG_SPACE(l)	\
	(FREEBSD32_ALIGN(sizeof(struct cmsghdr)) + FREEBSD32_ALIGN(l))

#define	FREEBSD32_CMSG_DATA(cmsg)	((unsigned char *)(cmsg) + \
				 FREEBSD32_ALIGN(sizeof(struct cmsghdr)))
static int
freebsd32_copy_msg_out(struct msghdr *msg, struct mbuf *control)
{
	struct cmsghdr *cm;
	void *data;
	socklen_t clen, datalen;
	int error;
	caddr_t ctlbuf;
	int len, maxlen, copylen;
	struct mbuf *m;
	error = 0;

	len    = msg->msg_controllen;
	maxlen = msg->msg_controllen;
	msg->msg_controllen = 0;

	m = control;
	ctlbuf = msg->msg_control;
      
	while (m && len > 0) {
		cm = mtod(m, struct cmsghdr *);
		clen = m->m_len;

		while (cm != NULL) {

			if (sizeof(struct cmsghdr) > clen ||
			    cm->cmsg_len > clen) {
				error = EINVAL;
				break;
			}	

			data   = CMSG_DATA(cm);
			datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;

			/* Adjust message length */
			cm->cmsg_len = FREEBSD32_ALIGN(sizeof(struct cmsghdr)) +
			    datalen;


			/* Copy cmsghdr */
			copylen = sizeof(struct cmsghdr);
			if (len < copylen) {
				msg->msg_flags |= MSG_CTRUNC;
				copylen = len;
			}

			error = copyout(cm,ctlbuf,copylen);
			if (error)
				goto exit;

			ctlbuf += FREEBSD32_ALIGN(copylen);
			len    -= FREEBSD32_ALIGN(copylen);

			if (len <= 0)
				break;

			/* Copy data */
			copylen = datalen;
			if (len < copylen) {
				msg->msg_flags |= MSG_CTRUNC;
				copylen = len;
			}

			error = copyout(data,ctlbuf,copylen);
			if (error)
				goto exit;

			ctlbuf += FREEBSD32_ALIGN(copylen);
			len    -= FREEBSD32_ALIGN(copylen);

			if (CMSG_SPACE(datalen) < clen) {
				clen -= CMSG_SPACE(datalen);
				cm = (struct cmsghdr *)
					((caddr_t)cm + CMSG_SPACE(datalen));
			} else {
				clen = 0;
				cm = NULL;
			}
		}	
		m = m->m_next;
	}

	msg->msg_controllen = (len <= 0) ? maxlen :  ctlbuf - (caddr_t)msg->msg_control;
	
exit:
	return (error);

}

int
freebsd32_recvmsg(td, uap)
	struct thread *td;
	struct freebsd32_recvmsg_args /* {
		int	s;
		struct	msghdr32 *msg;
		int	flags;
	} */ *uap;
{
	struct msghdr msg;
	struct msghdr32 m32;
	struct iovec *uiov, *iov;
	struct mbuf *control = NULL;
	struct mbuf **controlp;

	int error;
	error = copyin(uap->msg, &m32, sizeof(m32));
	if (error)
		return (error);
	error = freebsd32_copyinmsghdr(uap->msg, &msg);
	if (error)
		return (error);
	error = freebsd32_copyiniov((struct iovec32 *)(uintptr_t)m32.msg_iov,
	    m32.msg_iovlen, &iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_flags = uap->flags;
	uiov = msg.msg_iov;
	msg.msg_iov = iov;

	controlp = (msg.msg_control != NULL) ?  &control : NULL;
	error = kern_recvit(td, uap->s, &msg, NULL, UIO_USERSPACE, controlp);
	if (error == 0) {
		msg.msg_iov = uiov;
		
		if (control != NULL)
			error = freebsd32_copy_msg_out(&msg, control);
		
		if (error == 0)
			error = freebsd32_copyoutmsghdr(&msg, uap->msg);

		if (error == 0)
			error = freebsd32_copyoutiov(iov, m32.msg_iovlen,
			    (struct iovec32 *)(uintptr_t)m32.msg_iov, EMSGSIZE);
	}
	free(iov, M_IOV);

	if (control != NULL)
		m_freem(control);

	return (error);
}


static int
freebsd32_convert_msg_in(struct mbuf **controlp)
{
	struct mbuf *control = *controlp;
	struct cmsghdr *cm = mtod(control, struct cmsghdr *);
	void *data;
	socklen_t clen = control->m_len, datalen;
	int error;

	error = 0;
	*controlp = NULL;

	while (cm != NULL) {
		if (sizeof(struct cmsghdr) > clen || cm->cmsg_len > clen) {
			error = EINVAL;
			break;
		}

		data = FREEBSD32_CMSG_DATA(cm);
		datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;

		*controlp = sbcreatecontrol(data, datalen, cm->cmsg_type,
		    cm->cmsg_level);
		controlp = &(*controlp)->m_next;

		if (FREEBSD32_CMSG_SPACE(datalen) < clen) {
			clen -= FREEBSD32_CMSG_SPACE(datalen);
			cm = (struct cmsghdr *)
				((caddr_t)cm + FREEBSD32_CMSG_SPACE(datalen));
		} else {
			clen = 0;
			cm = NULL;
		}
	}

	m_freem(control);
	return (error);
}


int
freebsd32_sendmsg(struct thread *td,
		  struct freebsd32_sendmsg_args *uap)
{
	struct msghdr msg;
	struct msghdr32 m32;
	struct iovec *iov;
	struct mbuf *control = NULL;
	struct sockaddr *to = NULL;
	int error;

	error = copyin(uap->msg, &m32, sizeof(m32));
	if (error)
		return (error);
	error = freebsd32_copyinmsghdr(uap->msg, &msg);
	if (error)
		return (error);
	error = freebsd32_copyiniov((struct iovec32 *)(uintptr_t)m32.msg_iov,
	    m32.msg_iovlen, &iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_iov = iov;
	if (msg.msg_name != NULL) {
		error = getsockaddr(&to, msg.msg_name, msg.msg_namelen);
		if (error) {
			to = NULL;
			goto out;
		}
		msg.msg_name = to;
	}

	if (msg.msg_control) {
		if (msg.msg_controllen < sizeof(struct cmsghdr)) {
			error = EINVAL;
			goto out;
		}

		error = sockargs(&control, msg.msg_control,
		    msg.msg_controllen, MT_CONTROL);
		if (error)
			goto out;
		
		error = freebsd32_convert_msg_in(&control);
		if (error)
			goto out;
	}

	error = kern_sendit(td, uap->s, &msg, uap->flags, control,
	    UIO_USERSPACE);

out:
	free(iov, M_IOV);
	if (to)
		free(to, M_SONAME);
	return (error);
}

int
freebsd32_recvfrom(struct thread *td,
		   struct freebsd32_recvfrom_args *uap)
{
	struct msghdr msg;
	struct iovec aiov;
	int error;

	if (uap->fromlenaddr) {
		error = copyin((void *)(uintptr_t)uap->fromlenaddr,
		    &msg.msg_namelen, sizeof(msg.msg_namelen));
		if (error)
			return (error);
	} else {
		msg.msg_namelen = 0;
	}

	msg.msg_name = (void *)(uintptr_t)uap->from;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = (void *)(uintptr_t)uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = uap->flags;
	error = kern_recvit(td, uap->s, &msg,
	    (void *)(uintptr_t)uap->fromlenaddr, UIO_USERSPACE, NULL);
	return (error);
}

int
freebsd32_settimeofday(struct thread *td,
		       struct freebsd32_settimeofday_args *uap)
{
	struct timeval32 tv32;
	struct timeval tv, *tvp;
	struct timezone tz, *tzp;
	int error;

	if (uap->tv) {
		error = copyin(uap->tv, &tv32, sizeof(tv32));
		if (error)
			return (error);
		CP(tv32, tv, tv_sec);
		CP(tv32, tv, tv_usec);
		tvp = &tv;
	} else
		tvp = NULL;
	if (uap->tzp) {
		error = copyin(uap->tzp, &tz, sizeof(tz));
		if (error)
			return (error);
		tzp = &tz;
	} else
		tzp = NULL;
	return (kern_settimeofday(td, tvp, tzp));
}

int
freebsd32_utimes(struct thread *td, struct freebsd32_utimes_args *uap)
{
	struct timeval32 s32[2];
	struct timeval s[2], *sp;
	int error;

	if (uap->tptr != NULL) {
		error = copyin(uap->tptr, s32, sizeof(s32));
		if (error)
			return (error);
		CP(s32[0], s[0], tv_sec);
		CP(s32[0], s[0], tv_usec);
		CP(s32[1], s[1], tv_sec);
		CP(s32[1], s[1], tv_usec);
		sp = s;
	} else
		sp = NULL;
	return (kern_utimes(td, uap->path, UIO_USERSPACE, sp, UIO_SYSSPACE));
}

int
freebsd32_lutimes(struct thread *td, struct freebsd32_lutimes_args *uap)
{
	struct timeval32 s32[2];
	struct timeval s[2], *sp;
	int error;

	if (uap->tptr != NULL) {
		error = copyin(uap->tptr, s32, sizeof(s32));
		if (error)
			return (error);
		CP(s32[0], s[0], tv_sec);
		CP(s32[0], s[0], tv_usec);
		CP(s32[1], s[1], tv_sec);
		CP(s32[1], s[1], tv_usec);
		sp = s;
	} else
		sp = NULL;
	return (kern_lutimes(td, uap->path, UIO_USERSPACE, sp, UIO_SYSSPACE));
}

int
freebsd32_futimes(struct thread *td, struct freebsd32_futimes_args *uap)
{
	struct timeval32 s32[2];
	struct timeval s[2], *sp;
	int error;

	if (uap->tptr != NULL) {
		error = copyin(uap->tptr, s32, sizeof(s32));
		if (error)
			return (error);
		CP(s32[0], s[0], tv_sec);
		CP(s32[0], s[0], tv_usec);
		CP(s32[1], s[1], tv_sec);
		CP(s32[1], s[1], tv_usec);
		sp = s;
	} else
		sp = NULL;
	return (kern_futimes(td, uap->fd, sp, UIO_SYSSPACE));
}


int
freebsd32_adjtime(struct thread *td, struct freebsd32_adjtime_args *uap)
{
	struct timeval32 tv32;
	struct timeval delta, olddelta, *deltap;
	int error;

	if (uap->delta) {
		error = copyin(uap->delta, &tv32, sizeof(tv32));
		if (error)
			return (error);
		CP(tv32, delta, tv_sec);
		CP(tv32, delta, tv_usec);
		deltap = &delta;
	} else
		deltap = NULL;
	error = kern_adjtime(td, deltap, &olddelta);
	if (uap->olddelta && error == 0) {
		CP(olddelta, tv32, tv_sec);
		CP(olddelta, tv32, tv_usec);
		error = copyout(&tv32, uap->olddelta, sizeof(tv32));
	}
	return (error);
}

#ifdef COMPAT_FREEBSD4
int
freebsd4_freebsd32_statfs(struct thread *td, struct freebsd4_freebsd32_statfs_args *uap)
{
	struct statfs32 s32;
	struct statfs s;
	int error;

	error = kern_statfs(td, uap->path, UIO_USERSPACE, &s);
	if (error)
		return (error);
	copy_statfs(&s, &s32);
	return (copyout(&s32, uap->buf, sizeof(s32)));
}
#endif

#ifdef COMPAT_FREEBSD4
int
freebsd4_freebsd32_fstatfs(struct thread *td, struct freebsd4_freebsd32_fstatfs_args *uap)
{
	struct statfs32 s32;
	struct statfs s;
	int error;

	error = kern_fstatfs(td, uap->fd, &s);
	if (error)
		return (error);
	copy_statfs(&s, &s32);
	return (copyout(&s32, uap->buf, sizeof(s32)));
}
#endif

#ifdef COMPAT_FREEBSD4
int
freebsd4_freebsd32_fhstatfs(struct thread *td, struct freebsd4_freebsd32_fhstatfs_args *uap)
{
	struct statfs32 s32;
	struct statfs s;
	fhandle_t fh;
	int error;

	if ((error = copyin(uap->u_fhp, &fh, sizeof(fhandle_t))) != 0)
		return (error);
	error = kern_fhstatfs(td, fh, &s);
	if (error)
		return (error);
	copy_statfs(&s, &s32);
	return (copyout(&s32, uap->buf, sizeof(s32)));
}
#endif

int
freebsd32_semsys(struct thread *td, struct freebsd32_semsys_args *uap)
{
	/*
	 * Vector through to semsys if it is loaded.
	 */
	return sysent[SYS_semsys].sy_call(td, uap);
}

int
freebsd32_msgsys(struct thread *td, struct freebsd32_msgsys_args *uap)
{
	/*
	 * Vector through to msgsys if it is loaded.
	 */
	return sysent[SYS_msgsys].sy_call(td, uap);
}

int
freebsd32_shmsys(struct thread *td, struct freebsd32_shmsys_args *uap)
{
	/*
	 * Vector through to shmsys if it is loaded.
	 */
	return sysent[SYS_shmsys].sy_call(td, uap);
}

int
freebsd32_pread(struct thread *td, struct freebsd32_pread_args *uap)
{
	struct pread_args ap;

	ap.fd = uap->fd;
	ap.buf = uap->buf;
	ap.nbyte = uap->nbyte;
	ap.offset = (uap->offsetlo | ((off_t)uap->offsethi << 32));
	return (pread(td, &ap));
}

int
freebsd32_pwrite(struct thread *td, struct freebsd32_pwrite_args *uap)
{
	struct pwrite_args ap;

	ap.fd = uap->fd;
	ap.buf = uap->buf;
	ap.nbyte = uap->nbyte;
	ap.offset = (uap->offsetlo | ((off_t)uap->offsethi << 32));
	return (pwrite(td, &ap));
}

int
freebsd32_lseek(struct thread *td, struct freebsd32_lseek_args *uap)
{
	int error;
	struct lseek_args ap;
	off_t pos;

	ap.fd = uap->fd;
	ap.offset = (uap->offsetlo | ((off_t)uap->offsethi << 32));
	ap.whence = uap->whence;
	error = lseek(td, &ap);
	/* Expand the quad return into two parts for eax and edx */
	pos = *(off_t *)(td->td_retval);
	td->td_retval[0] = pos & 0xffffffff;	/* %eax */
	td->td_retval[1] = pos >> 32;		/* %edx */
	return error;
}

int
freebsd32_truncate(struct thread *td, struct freebsd32_truncate_args *uap)
{
	struct truncate_args ap;

	ap.path = uap->path;
	ap.length = (uap->lengthlo | ((off_t)uap->lengthhi << 32));
	return (truncate(td, &ap));
}

int
freebsd32_ftruncate(struct thread *td, struct freebsd32_ftruncate_args *uap)
{
	struct ftruncate_args ap;

	ap.fd = uap->fd;
	ap.length = (uap->lengthlo | ((off_t)uap->lengthhi << 32));
	return (ftruncate(td, &ap));
}

struct sf_hdtr32 {
	uint32_t headers;
	int hdr_cnt;
	uint32_t trailers;
	int trl_cnt;
};

static int
freebsd32_do_sendfile(struct thread *td,
    struct freebsd32_sendfile_args *uap, int compat)
{
	struct sendfile_args ap;
	struct sf_hdtr32 hdtr32;
	struct sf_hdtr hdtr;
	struct uio *hdr_uio, *trl_uio;
	struct iovec32 *iov32;
	int error;

	hdr_uio = trl_uio = NULL;

	ap.fd = uap->fd;
	ap.s = uap->s;
	ap.offset = (uap->offsetlo | ((off_t)uap->offsethi << 32));
	ap.nbytes = uap->nbytes;
	ap.hdtr = (struct sf_hdtr *)uap->hdtr;		/* XXX not used */
	ap.sbytes = uap->sbytes;
	ap.flags = uap->flags;

	if (uap->hdtr != NULL) {
		error = copyin(uap->hdtr, &hdtr32, sizeof(hdtr32));
		if (error)
			goto out;
		PTRIN_CP(hdtr32, hdtr, headers);
		CP(hdtr32, hdtr, hdr_cnt);
		PTRIN_CP(hdtr32, hdtr, trailers);
		CP(hdtr32, hdtr, trl_cnt);

		if (hdtr.headers != NULL) {
			iov32 = (struct iovec32 *)(uintptr_t)hdtr32.headers;
			error = freebsd32_copyinuio(iov32,
			    hdtr32.hdr_cnt, &hdr_uio);
			if (error)
				goto out;
		}
		if (hdtr.trailers != NULL) {
			iov32 = (struct iovec32 *)(uintptr_t)hdtr32.trailers;
			error = freebsd32_copyinuio(iov32,
			    hdtr32.trl_cnt, &trl_uio);
			if (error)
				goto out;
		}
	}

	error = kern_sendfile(td, &ap, hdr_uio, trl_uio, compat);
out:
	if (hdr_uio)
		free(hdr_uio, M_IOV);
	if (trl_uio)
		free(trl_uio, M_IOV);
	return (error);
}

#ifdef COMPAT_FREEBSD4
int
freebsd4_freebsd32_sendfile(struct thread *td,
    struct freebsd4_freebsd32_sendfile_args *uap)
{
	return (freebsd32_do_sendfile(td,
	    (struct freebsd32_sendfile_args *)uap, 1));
}
#endif

int
freebsd32_sendfile(struct thread *td, struct freebsd32_sendfile_args *uap)
{

	return (freebsd32_do_sendfile(td, uap, 0));
}

struct stat32 {
	dev_t	st_dev;
	ino_t	st_ino;
	mode_t	st_mode;
	nlink_t	st_nlink;
	uid_t	st_uid;
	gid_t	st_gid;
	dev_t	st_rdev;
	struct timespec32 st_atimespec;
	struct timespec32 st_mtimespec;
	struct timespec32 st_ctimespec;
	off_t	st_size;
	int64_t	st_blocks;
	u_int32_t st_blksize;
	u_int32_t st_flags;
	u_int32_t st_gen;
	struct timespec32 st_birthtimespec;
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec32));
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec32));
};


CTASSERT(sizeof(struct stat32) == 96);

static void
copy_stat( struct stat *in, struct stat32 *out)
{
	CP(*in, *out, st_dev);
	CP(*in, *out, st_ino);
	CP(*in, *out, st_mode);
	CP(*in, *out, st_nlink);
	CP(*in, *out, st_uid);
	CP(*in, *out, st_gid);
	CP(*in, *out, st_rdev);
	TS_CP(*in, *out, st_atimespec);
	TS_CP(*in, *out, st_mtimespec);
	TS_CP(*in, *out, st_ctimespec);
	CP(*in, *out, st_size);
	CP(*in, *out, st_blocks);
	CP(*in, *out, st_blksize);
	CP(*in, *out, st_flags);
	CP(*in, *out, st_gen);
}

int
freebsd32_stat(struct thread *td, struct freebsd32_stat_args *uap)
{
	struct stat sb;
	struct stat32 sb32;
	int error;

	error = kern_stat(td, uap->path, UIO_USERSPACE, &sb);
	if (error)
		return (error);
	copy_stat(&sb, &sb32);
	error = copyout(&sb32, uap->ub, sizeof (sb32));
	return (error);
}

int
freebsd32_fstat(struct thread *td, struct freebsd32_fstat_args *uap)
{
	struct stat ub;
	struct stat32 ub32;
	int error;

	error = kern_fstat(td, uap->fd, &ub);
	if (error)
		return (error);
	copy_stat(&ub, &ub32);
	error = copyout(&ub32, uap->ub, sizeof(ub32));
	return (error);
}

int
freebsd32_lstat(struct thread *td, struct freebsd32_lstat_args *uap)
{
	struct stat sb;
	struct stat32 sb32;
	int error;

	error = kern_lstat(td, uap->path, UIO_USERSPACE, &sb);
	if (error)
		return (error);
	copy_stat(&sb, &sb32);
	error = copyout(&sb32, uap->ub, sizeof (sb32));
	return (error);
}

/*
 * MPSAFE
 */
int
freebsd32_sysctl(struct thread *td, struct freebsd32_sysctl_args *uap)
{
	int error, name[CTL_MAXNAME];
	size_t j, oldlen;

	if (uap->namelen > CTL_MAXNAME || uap->namelen < 2)
		return (EINVAL);
 	error = copyin(uap->name, name, uap->namelen * sizeof(int));
 	if (error)
		return (error);
	mtx_lock(&Giant);
	if (uap->oldlenp)
		oldlen = fuword32(uap->oldlenp);
	else
		oldlen = 0;
	error = userland_sysctl(td, name, uap->namelen,
		uap->old, &oldlen, 1,
		uap->new, uap->newlen, &j, SCTL_MASK32);
	if (error && error != ENOMEM)
		goto done2;
	if (uap->oldlenp)
		suword32(uap->oldlenp, j);
done2:
	mtx_unlock(&Giant);
	return (error);
}

struct sigaction32 {
	u_int32_t	sa_u;
	int		sa_flags;
	sigset_t	sa_mask;
};

CTASSERT(sizeof(struct sigaction32) == 24);

int
freebsd32_sigaction(struct thread *td, struct freebsd32_sigaction_args *uap)
{
	struct sigaction32 s32;
	struct sigaction sa, osa, *sap;
	int error;

	if (uap->act) {
		error = copyin(uap->act, &s32, sizeof(s32));
		if (error)
			return (error);
		sa.sa_handler = PTRIN(s32.sa_u);
		CP(s32, sa, sa_flags);
		CP(s32, sa, sa_mask);
		sap = &sa;
	} else
		sap = NULL;
	error = kern_sigaction(td, uap->sig, sap, &osa, 0);
	if (error == 0 && uap->oact != NULL) {
		s32.sa_u = PTROUT(osa.sa_handler);
		CP(osa, s32, sa_flags);
		CP(osa, s32, sa_mask);
		error = copyout(&s32, uap->oact, sizeof(s32));
	}
	return (error);
}

#ifdef COMPAT_FREEBSD4
int
freebsd4_freebsd32_sigaction(struct thread *td,
			     struct freebsd4_freebsd32_sigaction_args *uap)
{
	struct sigaction32 s32;
	struct sigaction sa, osa, *sap;
	int error;

	if (uap->act) {
		error = copyin(uap->act, &s32, sizeof(s32));
		if (error)
			return (error);
		sa.sa_handler = PTRIN(s32.sa_u);
		CP(s32, sa, sa_flags);
		CP(s32, sa, sa_mask);
		sap = &sa;
	} else
		sap = NULL;
	error = kern_sigaction(td, uap->sig, sap, &osa, KSA_FREEBSD4);
	if (error == 0 && uap->oact != NULL) {
		s32.sa_u = PTROUT(osa.sa_handler);
		CP(osa, s32, sa_flags);
		CP(osa, s32, sa_mask);
		error = copyout(&s32, uap->oact, sizeof(s32));
	}
	return (error);
}
#endif

#ifdef COMPAT_43
struct osigaction32 {
	u_int32_t	sa_u;
	osigset_t	sa_mask;
	int		sa_flags;
};

#define	ONSIG	32

int
ofreebsd32_sigaction(struct thread *td,
			     struct ofreebsd32_sigaction_args *uap)
{
	struct osigaction32 s32;
	struct sigaction sa, osa, *sap;
	int error;

	if (uap->signum <= 0 || uap->signum >= ONSIG)
		return (EINVAL);

	if (uap->nsa) {
		error = copyin(uap->nsa, &s32, sizeof(s32));
		if (error)
			return (error);
		sa.sa_handler = PTRIN(s32.sa_u);
		CP(s32, sa, sa_flags);
		OSIG2SIG(s32.sa_mask, sa.sa_mask);
		sap = &sa;
	} else
		sap = NULL;
	error = kern_sigaction(td, uap->signum, sap, &osa, KSA_OSIGSET);
	if (error == 0 && uap->osa != NULL) {
		s32.sa_u = PTROUT(osa.sa_handler);
		CP(osa, s32, sa_flags);
		SIG2OSIG(osa.sa_mask, s32.sa_mask);
		error = copyout(&s32, uap->osa, sizeof(s32));
	}
	return (error);
}

int
ofreebsd32_sigprocmask(struct thread *td,
			       struct ofreebsd32_sigprocmask_args *uap)
{
	sigset_t set, oset;
	int error;

	OSIG2SIG(uap->mask, set);
	error = kern_sigprocmask(td, uap->how, &set, &oset, 1);
	SIG2OSIG(oset, td->td_retval[0]);
	return (error);
}

int
ofreebsd32_sigpending(struct thread *td,
			      struct ofreebsd32_sigpending_args *uap)
{
	struct proc *p = td->td_proc;
	sigset_t siglist;

	PROC_LOCK(p);
	siglist = p->p_siglist;
	SIGSETOR(siglist, td->td_siglist);
	PROC_UNLOCK(p);
	SIG2OSIG(siglist, td->td_retval[0]);
	return (0);
}

struct sigvec32 {
	u_int32_t	sv_handler;
	int		sv_mask;
	int		sv_flags;
};

int
ofreebsd32_sigvec(struct thread *td,
			  struct ofreebsd32_sigvec_args *uap)
{
	struct sigvec32 vec;
	struct sigaction sa, osa, *sap;
	int error;

	if (uap->signum <= 0 || uap->signum >= ONSIG)
		return (EINVAL);

	if (uap->nsv) {
		error = copyin(uap->nsv, &vec, sizeof(vec));
		if (error)
			return (error);
		sa.sa_handler = PTRIN(vec.sv_handler);
		OSIG2SIG(vec.sv_mask, sa.sa_mask);
		sa.sa_flags = vec.sv_flags;
		sa.sa_flags ^= SA_RESTART;
		sap = &sa;
	} else
		sap = NULL;
	error = kern_sigaction(td, uap->signum, sap, &osa, KSA_OSIGSET);
	if (error == 0 && uap->osv != NULL) {
		vec.sv_handler = PTROUT(osa.sa_handler);
		SIG2OSIG(osa.sa_mask, vec.sv_mask);
		vec.sv_flags = osa.sa_flags;
		vec.sv_flags &= ~SA_NOCLDWAIT;
		vec.sv_flags ^= SA_RESTART;
		error = copyout(&vec, uap->osv, sizeof(vec));
	}
	return (error);
}

int
ofreebsd32_sigblock(struct thread *td,
			    struct ofreebsd32_sigblock_args *uap)
{
	struct proc *p = td->td_proc;
	sigset_t set;

	OSIG2SIG(uap->mask, set);
	SIG_CANTMASK(set);
	PROC_LOCK(p);
	SIG2OSIG(td->td_sigmask, td->td_retval[0]);
	SIGSETOR(td->td_sigmask, set);
	PROC_UNLOCK(p);
	return (0);
}

int
ofreebsd32_sigsetmask(struct thread *td,
			      struct ofreebsd32_sigsetmask_args *uap)
{
	struct proc *p = td->td_proc;
	sigset_t set;

	OSIG2SIG(uap->mask, set);
	SIG_CANTMASK(set);
	PROC_LOCK(p);
	SIG2OSIG(td->td_sigmask, td->td_retval[0]);
	SIGSETLO(td->td_sigmask, set);
	signotify(td);
	PROC_UNLOCK(p);
	return (0);
}

int
ofreebsd32_sigsuspend(struct thread *td,
			      struct ofreebsd32_sigsuspend_args *uap)
{
	struct proc *p = td->td_proc;
	sigset_t mask;

	PROC_LOCK(p);
	td->td_oldsigmask = td->td_sigmask;
	td->td_pflags |= TDP_OLDMASK;
	OSIG2SIG(uap->mask, mask);
	SIG_CANTMASK(mask);
	SIGSETLO(td->td_sigmask, mask);
	signotify(td);
	while (msleep(&p->p_sigacts, &p->p_mtx, PPAUSE|PCATCH, "opause", 0) == 0)
		/* void */;
	PROC_UNLOCK(p);
	/* always return EINTR rather than ERESTART... */
	return (EINTR);
}

struct sigstack32 {
	u_int32_t	ss_sp;
	int		ss_onstack;
};

int
ofreebsd32_sigstack(struct thread *td,
			    struct ofreebsd32_sigstack_args *uap)
{
	struct sigstack32 s32;
	struct sigstack nss, oss;
	int error = 0;

	if (uap->nss != NULL) {
		error = copyin(uap->nss, &s32, sizeof(s32));
		if (error)
			return (error);
		nss.ss_sp = PTRIN(s32.ss_sp);
		CP(s32, nss, ss_onstack);
	}
	oss.ss_sp = td->td_sigstk.ss_sp;
	oss.ss_onstack = sigonstack(cpu_getstack(td));
	if (uap->nss != NULL) {
		td->td_sigstk.ss_sp = nss.ss_sp;
		td->td_sigstk.ss_size = 0;
		td->td_sigstk.ss_flags |= nss.ss_onstack & SS_ONSTACK;
		td->td_pflags |= TDP_ALTSTACK;
	}
	if (uap->oss != NULL) {
		s32.ss_sp = PTROUT(oss.ss_sp);
		CP(oss, s32, ss_onstack);
		error = copyout(&s32, uap->oss, sizeof(s32));
	}
	return (error);
}
#endif

int
freebsd32_nanosleep(struct thread *td, struct freebsd32_nanosleep_args *uap)
{
	struct timespec32 rmt32, rqt32;
	struct timespec rmt, rqt;
	int error;

	error = copyin(uap->rqtp, &rqt32, sizeof(rqt32));
	if (error)
		return (error);

	CP(rqt32, rqt, tv_sec);
	CP(rqt32, rqt, tv_nsec);

	if (uap->rmtp &&
	    !useracc((caddr_t)uap->rmtp, sizeof(rmt), VM_PROT_WRITE))
		return (EFAULT);
	error = kern_nanosleep(td, &rqt, &rmt);
	if (error && uap->rmtp) {
		int error2;

		CP(rmt, rmt32, tv_sec);
		CP(rmt, rmt32, tv_nsec);

		error2 = copyout(&rmt32, uap->rmtp, sizeof(rmt32));
		if (error2)
			error = error2;
	}
	return (error);
}

int
freebsd32_clock_gettime(struct thread *td,
			struct freebsd32_clock_gettime_args *uap)
{
	struct timespec	ats;
	struct timespec32 ats32;
	int error;

	error = kern_clock_gettime(td, uap->clock_id, &ats);
	if (error == 0) {
		CP(ats, ats32, tv_sec);
		CP(ats, ats32, tv_nsec);
		error = copyout(&ats32, uap->tp, sizeof(ats32));
	}
	return (error);
}

int
freebsd32_clock_settime(struct thread *td,
			struct freebsd32_clock_settime_args *uap)
{
	struct timespec	ats;
	struct timespec32 ats32;
	int error;

	error = copyin(uap->tp, &ats32, sizeof(ats32));
	if (error)
		return (error);
	CP(ats32, ats, tv_sec);
	CP(ats32, ats, tv_nsec);

	return (kern_clock_settime(td, uap->clock_id, &ats));
}

int
freebsd32_clock_getres(struct thread *td,
		       struct freebsd32_clock_getres_args *uap)
{
	struct timespec	ts;
	struct timespec32 ts32;
	int error;

	if (uap->tp == NULL)
		return (0);
	error = kern_clock_getres(td, uap->clock_id, &ts);
	if (error == 0) {
		CP(ts, ts32, tv_sec);
		CP(ts, ts32, tv_nsec);
		error = copyout(&ts32, uap->tp, sizeof(ts32));
	}
	return (error);
}

#if 0

int
freebsd32_xxx(struct thread *td, struct freebsd32_xxx_args *uap)
{
	int error;
	struct yyy32 *p32, s32;
	struct yyy *p = NULL, s;

	if (uap->zzz) {
		error = copyin(uap->zzz, &s32, sizeof(s32));
		if (error)
			return (error);
		/* translate in */
		p = &s;
	}
	error = kern_xxx(td, p);
	if (error)
		return (error);
	if (uap->zzz) {
		/* translate out */
		error = copyout(&s32, p32, sizeof(s32));
	}
	return (error);
}

#endif
