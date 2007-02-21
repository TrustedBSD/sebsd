# $FreeBSD: src/sbin/geom/class/Makefile,v 1.11 2006/03/17 18:54:30 ru Exp $

.include <bsd.own.mk>

SUBDIR=	concat
.if ${MK_OPENSSL} != "no"
SUBDIR+=eli
.endif
SUBDIR+=label
SUBDIR+=mirror
SUBDIR+=nop
SUBDIR+=raid3
SUBDIR+=shsec
SUBDIR+=stripe

.include <bsd.subdir.mk>
