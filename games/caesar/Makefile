#	@(#)Makefile	8.1 (Berkeley) 5/31/93
# $FreeBSD: src/games/caesar/Makefile,v 1.10 2005/05/01 19:34:22 stefanf Exp $

PROG=	caesar
DPADD=	${LIBM}
LDADD=	-lm
SCRIPTS=rot13.sh
MAN=	caesar.6
MLINKS=	caesar.6 rot13.6

WARNS?=	6

.include <bsd.prog.mk>
