# $FreeBSD: src/sbin/geom/class/eli/Makefile,v 1.3 2005/07/29 10:06:57 pjd Exp $

.PATH: ${.CURDIR}/../../misc ${.CURDIR}/../../../../sys/geom/eli ${.CURDIR}/../../../../sys/crypto/sha2

CLASS=	eli
SRCS=	g_eli_crypto.c
SRCS+=	g_eli_key.c
SRCS+=	pkcs5v2.c
SRCS+=	sha2.c

DPADD=	${LIBMD} ${LIBCRYPTO}
LDADD=	-lmd -lcrypto

WARNS?=	3

CFLAGS+=-I${.CURDIR}/../../../../sys

.include <bsd.lib.mk>
