# 	@(#)Makefile	8.1 (Berkeley) 7/19/93
# $FreeBSD: src/usr.bin/login/Makefile,v 1.51 2006/03/17 18:54:39 ru Exp $

.include <bsd.own.mk>

PROG=	login
SRCS=	login.c login_audit.c login_fbtab.c
CFLAGS+=-DLOGALL
DPADD=	${LIBUTIL} ${LIBPAM}
LDADD=	-lutil ${MINUSLPAM} -lbsm

.if ${MK_SETUID_LOGIN} != "no"
BINOWN=	root
BINMODE=4555
PRECIOUSPROG=
.endif

.if !defined(NO_SEBSD)
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libselinux/include
CFLAGS+=-I${.CURDIR}/../../sys
CFLAGS+=-I${.CURDIR}/../../sys/security/sebsd
CFLAGS+=-DSEBSD
DPADD+=	${LIBSELINUX}
LDADD+=	-lselinux -lsepol -lsecompat
.endif

.include <bsd.prog.mk>
