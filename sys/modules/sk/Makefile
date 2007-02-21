# $FreeBSD: src/sys/modules/sk/Makefile,v 1.13 2005/09/27 18:10:38 mlaier Exp $

.PATH: ${.CURDIR}/../../pci

KMOD=	if_sk
SRCS=	if_sk.c device_if.h bus_if.h pci_if.h
SRCS+=	miibus_if.h

.include <bsd.kmod.mk>
