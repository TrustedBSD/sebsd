#	@(#)Makefile	8.1 (Berkeley) 6/12/93
# $FreeBSD: src/usr.bin/netstat/Makefile,v 1.32 2006/03/17 18:54:39 ru Exp $

.include <bsd.own.mk>

PROG=	netstat
SRCS=	if.c inet.c inet6.c main.c mbuf.c mcast.c mroute.c route.c \
	unix.c atalk.c netgraph.c mroute6.c ipsec.c bpf.c pfkey.c

WARNS?=	2
NO_WERROR=

CFLAGS+=-DIPSEC
CFLAGS+=-DFAST_IPSEC
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DINET6
.endif

BINGRP=	kmem
BINMODE=2555
DPADD=	${LIBKVM} ${LIBMEMSTAT} ${LIBNETGRAPH} ${LIBUTIL}
LDADD=	-lkvm -lmemstat -lnetgraph -lutil

.if ${MK_IPX_SUPPORT} != "no"
SRCS+=	ipx.c
DPADD+=	${LIBIPX}
LDADD+=	-lipx
CFLAGS+=-DIPX
.endif

.include <bsd.prog.mk>
