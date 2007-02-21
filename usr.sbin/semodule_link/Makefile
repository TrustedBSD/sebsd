# $FreeBSD$

.PATH:	${.CURDIR}/../../contrib/sebsd/policycoreutils/semodule_link

PROG=	semodule_link
MAN=	semodule_link.8
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libsepol/include
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libsemanage/include
CFLAGS+=-I${.CURDIR}/../../sys

LDADD=	-lsemanage -lselinux -lsepol -lsecompat
DPADD=	${LIBSEMANAGE} ${LIBSELINUX} ${LIBSEPOL} ${LIBSECOMPAT}

WARNS=	0

MAINTAINER=	cboss@tislabs.com

.include <bsd.prog.mk>
