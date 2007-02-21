# $Id$
# $FreeBSD: src/sys/modules/netgraph/bluetooth/h4/Makefile,v 1.6 2006/02/18 23:49:27 yar Exp $

.PATH: ${.CURDIR}/../../../../netgraph/bluetooth/drivers/h4

CFLAGS+=	-I${.CURDIR}/../../../../netgraph/bluetooth/include \
		-I${.CURDIR}/../../../../netgraph/bluetooth/drivers/h4

KMOD=		ng_h4
SRCS=		ng_h4.c

.include <bsd.kmod.mk>
