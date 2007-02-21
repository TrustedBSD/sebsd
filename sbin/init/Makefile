#	@(#)Makefile	8.1 (Berkeley) 7/19/93
# $FreeBSD: src/sbin/init/Makefile,v 1.33 2006/02/28 08:02:28 luigi Exp $

PROG=	init
MAN=	init.8
MLINKS=	init.8 securelevel.8
PRECIOUSPROG=
INSTALLFLAGS=-b -B.bak
WARNS?=	6
CFLAGS+=-DDEBUGSHELL -DSECURE -DLOGIN_CAP -DCOMPAT_SYSV_INIT
DPADD=	${LIBUTIL} ${LIBCRYPT}
LDADD=	-lutil -lcrypt

NO_SHARED?=	YES

.include <bsd.prog.mk>
