/*-
 * Copyright (c) 1980, 1986, 1993
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
 *	@(#)raw_usrreq.c	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/raw_usrreq.c,v 1.37 2005/01/07 01:45:35 imp Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sx.h>
#include <sys/systm.h>
#include <sys/capability.h>

#include <net/raw_cb.h>

MTX_SYSINIT(rawcb_mtx, &rawcb_mtx, "rawcb", MTX_DEF);

/*
 * Initialize raw connection block q.
 */
void
raw_init()
{

	LIST_INIT(&rawcb_list);
}


/*
 * Raw protocol input routine.  Find the socket
 * associated with the packet(s) and move them over.  If
 * nothing exists for this packet, drop it.
 */
/*
 * Raw protocol interface.
 */
void
raw_input(m0, proto, src, dst)
	struct mbuf *m0;
	register struct sockproto *proto;
	struct sockaddr *src, *dst;
{
	register struct rawcb *rp;
	register struct mbuf *m = m0;
	struct socket *last;

	last = 0;
	mtx_lock(&rawcb_mtx);
	LIST_FOREACH(rp, &rawcb_list, list) {
		if (rp->rcb_proto.sp_family != proto->sp_family)
			continue;
		if (rp->rcb_proto.sp_protocol  &&
		    rp->rcb_proto.sp_protocol != proto->sp_protocol)
			continue;
		/*
		 * We assume the lower level routines have
		 * placed the address in a canonical format
		 * suitable for a structure comparison.
		 *
		 * Note that if the lengths are not the same
		 * the comparison will fail at the first byte.
		 */
#define	equal(a1, a2) \
  (bcmp((caddr_t)(a1), (caddr_t)(a2), a1->sa_len) == 0)
		if (rp->rcb_laddr && !equal(rp->rcb_laddr, dst))
			continue;
		if (rp->rcb_faddr && !equal(rp->rcb_faddr, src))
			continue;
		if (last) {
			struct mbuf *n;
			n = m_copy(m, 0, (int)M_COPYALL);
			if (n) {
				if (sbappendaddr(&last->so_rcv, src,
				    n, (struct mbuf *)0) == 0)
					/* should notify about lost packet */
					m_freem(n);
				else {
					sorwakeup(last);
				}
			}
		}
		last = rp->rcb_socket;
	}
	if (last) {
		if (sbappendaddr(&last->so_rcv, src,
		    m, (struct mbuf *)0) == 0)
			m_freem(m);
		else {
			sorwakeup(last);
		}
	} else
		m_freem(m);
	mtx_unlock(&rawcb_mtx);
}

/*ARGSUSED*/
void
raw_ctlinput(cmd, arg, dummy)
	int cmd;
	struct sockaddr *arg;
	void *dummy;
{

	if (cmd < 0 || cmd >= PRC_NCMDS)
		return;
	/* INCOMPLETE */
}

static int
raw_uabort(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	raw_disconnect(rp);
	soisdisconnected(so);
	ACCEPT_LOCK();
	SOCK_LOCK(so);
	sotryfree(so);
	return 0;
}

/* pru_accept is EOPNOTSUPP */

static int
raw_uattach(struct socket *so, int proto, struct thread *td)
{
	struct rawcb *rp = sotorawcb(so);
	int error;

	if (rp == 0)
		return EINVAL;
	if (td && (error = cap_check(td, CAP_NET_RAW)) != 0)
		return error;
	return raw_attach(so, proto);
}

static int
raw_ubind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	return EINVAL;
}

static int
raw_uconnect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	return EINVAL;
}

/* pru_connect2 is EOPNOTSUPP */
/* pru_control is EOPNOTSUPP */

static int
raw_udetach(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;

	raw_detach(rp);
	return 0;
}

static int
raw_udisconnect(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	if (rp->rcb_faddr == 0) {
		return ENOTCONN;
	}
	raw_disconnect(rp);
	soisdisconnected(so);
	return 0;
}

/* pru_listen is EOPNOTSUPP */

static int
raw_upeeraddr(struct socket *so, struct sockaddr **nam)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	if (rp->rcb_faddr == 0) {
		return ENOTCONN;
	}
	*nam = sodupsockaddr(rp->rcb_faddr, M_WAITOK);
	return 0;
}

/* pru_rcvd is EOPNOTSUPP */
/* pru_rcvoob is EOPNOTSUPP */

static int
raw_usend(struct socket *so, int flags, struct mbuf *m,
	  struct sockaddr *nam, struct mbuf *control, struct thread *td)
{
	int error;
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0) {
		error = EINVAL;
		goto release;
	}

	if (flags & PRUS_OOB) {
		error = EOPNOTSUPP;
		goto release;
	}

	if (control && control->m_len) {
		error = EOPNOTSUPP;
		goto release;
	}
	if (nam) {
		if (rp->rcb_faddr) {
			error = EISCONN;
			goto release;
		}
		rp->rcb_faddr = nam;
	} else if (rp->rcb_faddr == 0) {
		error = ENOTCONN;
		goto release;
	}
	error = (*so->so_proto->pr_output)(m, so);
	m = NULL;
	if (nam)
		rp->rcb_faddr = 0;
release:
	if (m != NULL)
		m_freem(m);
	return (error);
}

/* pru_sense is null */

static int
raw_ushutdown(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	socantsendmore(so);
	return 0;
}

static int
raw_usockaddr(struct socket *so, struct sockaddr **nam)
{
	struct rawcb *rp = sotorawcb(so);

	if (rp == 0)
		return EINVAL;
	if (rp->rcb_laddr == 0)
		return EINVAL;
	*nam = sodupsockaddr(rp->rcb_laddr, M_WAITOK);
	return 0;
}

struct pr_usrreqs raw_usrreqs = {
	.pru_abort =		raw_uabort,
	.pru_attach =		raw_uattach,
	.pru_bind =		raw_ubind,
	.pru_connect =		raw_uconnect,
	.pru_detach =		raw_udetach, 
	.pru_disconnect =	raw_udisconnect,
	.pru_peeraddr =		raw_upeeraddr,
	.pru_send =		raw_usend,
	.pru_shutdown =		raw_ushutdown,
	.pru_sockaddr =		raw_usockaddr,
};
