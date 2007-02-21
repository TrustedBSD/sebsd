# $FreeBSD: $

.PATH: ${.CURDIR} ${.CURDIR}/../../contrib/sebsd/policycoreutils/setfiles

PROG=	setfiles
MAN=	setfiles.8
SRCS=	setfiles.c

CFLAGS+= -Wall -I${.CURDIR}/../../sys/security/sebsd/avc
CFLAGS+= -I${.CURDIR}/../../sys/security/sebsd
CFLAGS+= -I${.CURDIR}/../../sys
CFLAGS+= -I${.CURDIR}/../../contrib/sebsd/libselinux/include
CFLAGS+= -I${.CURDIR}/../../contrib/sebsd/libsepol/include

LDADD=	-lselinux -lsepol -lsecompat
DPADD=	${LIBSELINUX} ${LIBSEPOL} ${LIBSECOMPAT}

WARNS=	0

MAINTAINER=	cboss@tislabs.com

.include <bsd.prog.mk>
