#$FreeBSD: src/sys/modules/em/Makefile,v 1.5 2005/09/27 18:10:34 mlaier Exp $

.PATH: ${.CURDIR}/../../dev/em

KMOD=	if_em
SRCS=	if_em.c if_em_hw.c
SRCS+=	device_if.h bus_if.h pci_if.h

.include <bsd.kmod.mk>
