/*-
 * Copyright (c) 1994-1995 S�ren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer 
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
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
__FBSDID("$FreeBSD: src/sys/compat/linux/linux_signal.c,v 1.54 2006/03/19 11:10:33 ru Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>

#include "opt_compat.h"

#ifdef COMPAT_LINUX32
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>

void
linux_to_bsd_sigset(l_sigset_t *lss, sigset_t *bss)
{
	int b, l;

	SIGEMPTYSET(*bss);
	bss->__bits[0] = lss->__bits[0] & ~((1U << LINUX_SIGTBLSZ) - 1);
	bss->__bits[1] = lss->__bits[1];
	for (l = 1; l <= LINUX_SIGTBLSZ; l++) {
		if (LINUX_SIGISMEMBER(*lss, l)) {
#ifdef __alpha__
			b = _SIG_IDX(l);
#else
			b = linux_to_bsd_signal[_SIG_IDX(l)];
#endif
			if (b)
				SIGADDSET(*bss, b);
		}
	}
}

void
bsd_to_linux_sigset(sigset_t *bss, l_sigset_t *lss)
{
	int b, l;

	LINUX_SIGEMPTYSET(*lss);
	lss->__bits[0] = bss->__bits[0] & ~((1U << LINUX_SIGTBLSZ) - 1);
	lss->__bits[1] = bss->__bits[1];
	for (b = 1; b <= LINUX_SIGTBLSZ; b++) {
		if (SIGISMEMBER(*bss, b)) {
#ifdef __alpha__
			l = _SIG_IDX(b);
#else
			l = bsd_to_linux_signal[_SIG_IDX(b)];
#endif
			if (l)
				LINUX_SIGADDSET(*lss, l);
		}
	}
}

static void
linux_to_bsd_sigaction(l_sigaction_t *lsa, struct sigaction *bsa)
{

	linux_to_bsd_sigset(&lsa->lsa_mask, &bsa->sa_mask);
	bsa->sa_handler = PTRIN(lsa->lsa_handler);
	bsa->sa_flags = 0;
	if (lsa->lsa_flags & LINUX_SA_NOCLDSTOP)
		bsa->sa_flags |= SA_NOCLDSTOP;
	if (lsa->lsa_flags & LINUX_SA_NOCLDWAIT)
		bsa->sa_flags |= SA_NOCLDWAIT;
	if (lsa->lsa_flags & LINUX_SA_SIGINFO)
		bsa->sa_flags |= SA_SIGINFO;
	if (lsa->lsa_flags & LINUX_SA_ONSTACK)
		bsa->sa_flags |= SA_ONSTACK;
	if (lsa->lsa_flags & LINUX_SA_RESTART)
		bsa->sa_flags |= SA_RESTART;
	if (lsa->lsa_flags & LINUX_SA_ONESHOT)
		bsa->sa_flags |= SA_RESETHAND;
	if (lsa->lsa_flags & LINUX_SA_NOMASK)
		bsa->sa_flags |= SA_NODEFER;
}

static void
bsd_to_linux_sigaction(struct sigaction *bsa, l_sigaction_t *lsa)
{

	bsd_to_linux_sigset(&bsa->sa_mask, &lsa->lsa_mask);
#ifdef COMPAT_LINUX32
	lsa->lsa_handler = (uintptr_t)bsa->sa_handler;
#else
	lsa->lsa_handler = bsa->sa_handler;
#endif
	lsa->lsa_restorer = 0;		/* unsupported */
	lsa->lsa_flags = 0;
	if (bsa->sa_flags & SA_NOCLDSTOP)
		lsa->lsa_flags |= LINUX_SA_NOCLDSTOP;
	if (bsa->sa_flags & SA_NOCLDWAIT)
		lsa->lsa_flags |= LINUX_SA_NOCLDWAIT;
	if (bsa->sa_flags & SA_SIGINFO)
		lsa->lsa_flags |= LINUX_SA_SIGINFO;
	if (bsa->sa_flags & SA_ONSTACK)
		lsa->lsa_flags |= LINUX_SA_ONSTACK;
	if (bsa->sa_flags & SA_RESTART)
		lsa->lsa_flags |= LINUX_SA_RESTART;
	if (bsa->sa_flags & SA_RESETHAND)
		lsa->lsa_flags |= LINUX_SA_ONESHOT;
	if (bsa->sa_flags & SA_NODEFER)
		lsa->lsa_flags |= LINUX_SA_NOMASK;
}

int
linux_do_sigaction(struct thread *td, int linux_sig, l_sigaction_t *linux_nsa,
		   l_sigaction_t *linux_osa)
{
	struct sigaction act, oact, *nsa, *osa;
	int error, sig;

	if (linux_sig <= 0 || linux_sig > LINUX_NSIG)
		return (EINVAL);

	osa = (linux_osa != NULL) ? &oact : NULL;
	if (linux_nsa != NULL) {
		nsa = &act;
		linux_to_bsd_sigaction(linux_nsa, nsa);
	} else
		nsa = NULL;

#ifndef __alpha__
	if (linux_sig <= LINUX_SIGTBLSZ)
		sig = linux_to_bsd_signal[_SIG_IDX(linux_sig)];
	else
#endif
		sig = linux_sig;

	error = kern_sigaction(td, sig, nsa, osa, 0);
	if (error)
		return (error);

	if (linux_osa != NULL)
		bsd_to_linux_sigaction(osa, linux_osa);

	return (0);
}


#ifndef __alpha__
int
linux_signal(struct thread *td, struct linux_signal_args *args)
{
	l_sigaction_t nsa, osa;
	int error;

#ifdef DEBUG
	if (ldebug(signal))
		printf(ARGS(signal, "%d, %p"),
		    args->sig, (void *)(uintptr_t)args->handler);
#endif

	nsa.lsa_handler = args->handler;
	nsa.lsa_flags = LINUX_SA_ONESHOT | LINUX_SA_NOMASK;
	LINUX_SIGEMPTYSET(nsa.lsa_mask);

	error = linux_do_sigaction(td, args->sig, &nsa, &osa);
	td->td_retval[0] = (int)(intptr_t)osa.lsa_handler;

	return (error);
}
#endif	/*!__alpha__*/

int
linux_rt_sigaction(struct thread *td, struct linux_rt_sigaction_args *args)
{
	l_sigaction_t nsa, osa;
	int error;

#ifdef DEBUG
	if (ldebug(rt_sigaction))
		printf(ARGS(rt_sigaction, "%ld, %p, %p, %ld"),
		    (long)args->sig, (void *)args->act,
		    (void *)args->oact, (long)args->sigsetsize);
#endif

	if (args->sigsetsize != sizeof(l_sigset_t))
		return (EINVAL);

	if (args->act != NULL) {
		error = copyin(args->act, &nsa, sizeof(l_sigaction_t));
		if (error)
			return (error);
	}

	error = linux_do_sigaction(td, args->sig,
				   args->act ? &nsa : NULL,
				   args->oact ? &osa : NULL);

	if (args->oact != NULL && !error) {
		error = copyout(&osa, args->oact, sizeof(l_sigaction_t));
	}

	return (error);
}

static int
linux_do_sigprocmask(struct thread *td, int how, l_sigset_t *new,
		     l_sigset_t *old)
{
	sigset_t omask, nmask;
	sigset_t *nmaskp;
	int error;

	td->td_retval[0] = 0;

	switch (how) {
	case LINUX_SIG_BLOCK:
		how = SIG_BLOCK;
		break;
	case LINUX_SIG_UNBLOCK:
		how = SIG_UNBLOCK;
		break;
	case LINUX_SIG_SETMASK:
		how = SIG_SETMASK;
		break;
	default:
		return (EINVAL);
	}
	if (new != NULL) {
		linux_to_bsd_sigset(new, &nmask);
		nmaskp = &nmask;
	} else
		nmaskp = NULL;
	error = kern_sigprocmask(td, how, nmaskp, &omask, 0);
	if (error == 0 && old != NULL)
		bsd_to_linux_sigset(&omask, old);

	return (error);
}

#ifndef __alpha__
int
linux_sigprocmask(struct thread *td, struct linux_sigprocmask_args *args)
{
	l_osigset_t mask;
	l_sigset_t set, oset;
	int error;

#ifdef DEBUG
	if (ldebug(sigprocmask))
		printf(ARGS(sigprocmask, "%d, *, *"), args->how);
#endif

	if (args->mask != NULL) {
		error = copyin(args->mask, &mask, sizeof(l_osigset_t));
		if (error)
			return (error);
		LINUX_SIGEMPTYSET(set);
		set.__bits[0] = mask;
	}

	error = linux_do_sigprocmask(td, args->how,
				     args->mask ? &set : NULL,
				     args->omask ? &oset : NULL);

	if (args->omask != NULL && !error) {
		mask = oset.__bits[0];
		error = copyout(&mask, args->omask, sizeof(l_osigset_t));
	}

	return (error);
}
#endif	/*!__alpha__*/

int
linux_rt_sigprocmask(struct thread *td, struct linux_rt_sigprocmask_args *args)
{
	l_sigset_t set, oset;
	int error;

#ifdef DEBUG
	if (ldebug(rt_sigprocmask))
		printf(ARGS(rt_sigprocmask, "%d, %p, %p, %ld"),
		    args->how, (void *)args->mask,
		    (void *)args->omask, (long)args->sigsetsize);
#endif

	if (args->sigsetsize != sizeof(l_sigset_t))
		return EINVAL;

	if (args->mask != NULL) {
		error = copyin(args->mask, &set, sizeof(l_sigset_t));
		if (error)
			return (error);
	}

	error = linux_do_sigprocmask(td, args->how,
				     args->mask ? &set : NULL,
				     args->omask ? &oset : NULL);

	if (args->omask != NULL && !error) {
		error = copyout(&oset, args->omask, sizeof(l_sigset_t));
	}

	return (error);
}

#ifndef __alpha__
int
linux_sgetmask(struct thread *td, struct linux_sgetmask_args *args)
{
	struct proc *p = td->td_proc;
	l_sigset_t mask;

#ifdef DEBUG
	if (ldebug(sgetmask))
		printf(ARGS(sgetmask, ""));
#endif

	PROC_LOCK(p);
	bsd_to_linux_sigset(&td->td_sigmask, &mask);
	PROC_UNLOCK(p);
	td->td_retval[0] = mask.__bits[0];
	return (0);
}

int
linux_ssetmask(struct thread *td, struct linux_ssetmask_args *args)
{
	struct proc *p = td->td_proc;
	l_sigset_t lset;
	sigset_t bset;

#ifdef DEBUG
	if (ldebug(ssetmask))
		printf(ARGS(ssetmask, "%08lx"), (unsigned long)args->mask);
#endif

	PROC_LOCK(p);
	bsd_to_linux_sigset(&td->td_sigmask, &lset);
	td->td_retval[0] = lset.__bits[0];
	LINUX_SIGEMPTYSET(lset);
	lset.__bits[0] = args->mask;
	linux_to_bsd_sigset(&lset, &bset);
	td->td_sigmask = bset;
	SIG_CANTMASK(td->td_sigmask);
	signotify(td);
	PROC_UNLOCK(p);
	return (0);
}

/*
 * MPSAFE
 */
int
linux_sigpending(struct thread *td, struct linux_sigpending_args *args)
{
	struct proc *p = td->td_proc;
	sigset_t bset;
	l_sigset_t lset;
	l_osigset_t mask;

#ifdef DEBUG
	if (ldebug(sigpending))
		printf(ARGS(sigpending, "*"));
#endif

	PROC_LOCK(p);
	bset = p->p_siglist;
	SIGSETOR(bset, td->td_siglist);
	SIGSETAND(bset, td->td_sigmask);
	PROC_UNLOCK(p);
	bsd_to_linux_sigset(&bset, &lset);
	mask = lset.__bits[0];
	return (copyout(&mask, args->mask, sizeof(mask)));
}
#endif	/*!__alpha__*/

int
linux_kill(struct thread *td, struct linux_kill_args *args)
{
	struct kill_args /* {
	    int pid;
	    int signum;
	} */ tmp;

#ifdef DEBUG
	if (ldebug(kill))
		printf(ARGS(kill, "%d, %d"), args->pid, args->signum);
#endif

	/*
	 * Allow signal 0 as a means to check for privileges
	 */
	if (args->signum < 0 || args->signum > LINUX_NSIG)
		return EINVAL;

#ifndef __alpha__
	if (args->signum > 0 && args->signum <= LINUX_SIGTBLSZ)
		tmp.signum = linux_to_bsd_signal[_SIG_IDX(args->signum)];
	else
#endif
		tmp.signum = args->signum;

	tmp.pid = args->pid;
	return (kill(td, &tmp));
}
