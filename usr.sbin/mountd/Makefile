#	From: @(#)Makefile	8.3 (Berkeley) 1/25/94
# $FreeBSD: src/usr.sbin/mountd/Makefile,v 1.16 2005/08/24 19:17:06 pjd Exp $

PROG=	mountd
MAN=	exports.5 netgroup.5 mountd.8

WARNS?=	2

DPADD=	${LIBUTIL}
LDADD=	-lutil

.include <bsd.prog.mk>
