# $FreeBSD: src/bin/ed/Makefile,v 1.32 2006/03/17 18:54:20 ru Exp $

.include <bsd.own.mk>

PROG=	ed
SRCS=	buf.c cbc.c glbl.c io.c main.c re.c sub.c undo.c
LINKS=	${BINDIR}/ed ${BINDIR}/red
MLINKS=	ed.1 red.1

.if ${MK_OPENSSL} != "no"
CFLAGS+=-DDES
WARNS?=	2
DPADD=	${LIBCRYPTO}
LDADD=	-lcrypto
.endif

.include <bsd.prog.mk>
