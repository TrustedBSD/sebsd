# $FreeBSD: src/usr.sbin/named-checkzone/Makefile,v 1.4 2005/07/25 14:44:11 des Exp $

BIND_DIR=	${.CURDIR}/../../contrib/bind9
LIB_BIND_REL=	../../lib/bind
LIB_BIND_DIR=	${.CURDIR}/${LIB_BIND_REL}
SRCDIR=		${BIND_DIR}/bin/check

.include	"${LIB_BIND_DIR}/config.mk"

PROG=		named-checkzone

.PATH: ${SRCDIR}
SRCS+=		named-checkzone.c check-tool.c

CFLAGS+=	-I${LIB_BIND_DIR}

DPADD+=		${BIND_DPADD} ${CRYPTO_DPADD}
LDADD+=		${BIND_LDADD} ${CRYPTO_LDADD}

MAN=		named-checkzone.8

.include <bsd.prog.mk>
