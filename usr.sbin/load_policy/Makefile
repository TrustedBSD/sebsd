#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: src/usr.bin/nice/Makefile,v 1.4 2002/02/08 22:31:43 markm Exp $

.PATH: ${.CURDIR}/../../contrib/sebsd/policycoreutils/load_policy

PROG=	load_policy
MAN=	load_policy.8


LDADD=	-lselinux -lsepol -lsecompat
DPADD=	${LIBSELINUX} ${LIBSEPOL} ${LIBSECOMPAT} 

SRCS=	load_policy.c

CFLAGS+=-I${.CURDIR}/../../lib/libselinux
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libselinux/include
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libsepol/include

.include <bsd.prog.mk>
