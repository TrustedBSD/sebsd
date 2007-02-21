# From:	@(#)Makefile	8.1 (Berkeley) 7/19/93
# $FreeBSD: src/release/picobsd/tinyware/login/Makefile,v 1.5 2006/03/17 18:54:30 ru Exp $

.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../../../usr.bin/login

PROG=	login
SRCS=	pico-login.c login_access.c login_fbtab.c
MAN=	login.1 login.access.5

CFLAGS+=-DLOGIN_ACCESS -DLOGALL

DPADD=	${LIBUTIL} ${LIBCRYPT}
LDADD=	-lutil -lcrypt

.if ${MK_PAM_SUPPORT} != "no"
CFLAGS+= -DUSE_PAM
DPADD+=	${LIBPAM}
LDADD+=	${MINUSLPAM}
.endif

BINOWN=	root
BINMODE=4555
PRECIOUSPROG=

.include <bsd.prog.mk>
