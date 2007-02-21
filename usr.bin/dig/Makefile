# $FreeBSD: src/usr.bin/dig/Makefile,v 1.12 2005/07/25 14:44:10 des Exp $

BIND_DIR=	${.CURDIR}/../../contrib/bind9
LIB_BIND_REL=	../../lib/bind
LIB_BIND_DIR=	${.CURDIR}/${LIB_BIND_REL}
SRCDIR=		${BIND_DIR}/bin/dig

.include	"${LIB_BIND_DIR}/config.mk"

PROG=		dig

.PATH: ${SRCDIR}
SRCS+=		dig.c dighost.c

CFLAGS+=	-I${SRCDIR}/include

DPADD+=		${BIND_DPADD} ${CRYPTO_DPADD}
LDADD+=		${BIND_LDADD} ${CRYPTO_LDADD}

.include <bsd.prog.mk>
