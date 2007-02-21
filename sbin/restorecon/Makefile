# $FreeBSD$

.PATH:	${.CURDIR}/../../contrib/sebsd/policycoreutils/restorecon

PROG=	restorecon
MAN=	restorecon.8
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libsepol/include
CFLAGS+=-I${.CURDIR}/../../sys

LDADD=	-lselinux -lsepol -lsecompat
DPADD=	${LIBSELINUX} ${LIBSEPOL} ${LIBSECOMPAT}

WARNS=	0

MAINTAINER=	cboss@tislabs.com

.include <bsd.prog.mk>
