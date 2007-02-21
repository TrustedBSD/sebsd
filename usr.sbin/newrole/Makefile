#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: src/usr.bin/nice/Makefile,v 1.4 2002/02/08 22:31:43 markm Exp $

POLICYCOREUTILS=${.CURDIR}/../../contrib/sebsd/policycoreutils

VERSION != cat ${POLICYCOREUTILS}/VERSION

.PATH: ${POLICYCOREUTILS}/newrole

PROG=	newrole

LDADD=	-lselinux -lsepol -lpam -lsecompat
DPADD=	${LIBSELINUX} ${LIBSEPOL} ${LIBPAM} ${LIBSECOMPAT}

SRCS=	newrole.c 

CFLAGS+=-DUSE_PAM -DVERSION=\"$(VERSION)\" -DPACKAGE="\"policycoreutils\""
CFLAGS+=-I${.CURDIR}/../../lib/libselinux
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libselinux/include

.include <bsd.prog.mk>
