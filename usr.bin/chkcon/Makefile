# $FreeBSD$

.PATH:	${.CURDIR}/../../contrib/sebsd/libsepol/utils

PROG=	chkcon
NO_MAN=	yes
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libsepol/include
CFLAGS+=-I${.CURDIR}/../../sys

LDADD=	-lsepol -lsecompat
DPADD=	${LIBSEPOL} ${LIBSECOMPAT} 

WARNS=	0

MAINTAINER=	cboss@tislabs.com

.include <bsd.prog.mk>
