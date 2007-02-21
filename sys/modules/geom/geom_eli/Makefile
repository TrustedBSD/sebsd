# $FreeBSD: src/sys/modules/geom/geom_eli/Makefile,v 1.2 2006/02/11 12:45:01 pjd Exp $

.PATH: ${.CURDIR}/../../../geom/eli

KMOD=	geom_eli
SRCS=	g_eli.c g_eli_crypto.c g_eli_ctl.c g_eli_key.c pkcs5v2.c vnode_if.h
WARNS?=	2

.include <bsd.kmod.mk>
