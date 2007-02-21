# $FreeBSD: src/lib/libmp/Makefile,v 1.11 2005/11/10 18:07:06 ru Exp $

LIB=		mp
SHLIB_MAJOR=	5
DPADD=		${LIBCRYPTO}
LDADD=		-lcrypto
MAN=		libmp.3
INCS=		mp.h
SRCS=		mpasbn.c

WARNS?=		0
CFLAGS+=	-I${.CURDIR}/../../crypto

.include <bsd.lib.mk>
