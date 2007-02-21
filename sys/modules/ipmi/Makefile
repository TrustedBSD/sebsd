# $FreeBSD: src/sys/modules/ipmi/Makefile,v 1.1 2006/02/10 20:51:35 ambrisko Exp $

.PATH: ${.CURDIR}/../../dev/ipmi

KMOD=	ipmi
SRCS=	ipmi.c ipmi_pci.c ipmi_smbios.c
SRCS+=	bus_if.h device_if.h pci_if.h vnode_if.h

.include <bsd.kmod.mk>
