# $FreeBSD: src/sys/modules/slhci/Makefile,v 1.1 2005/07/14 15:57:01 takawata Exp $

.PATH: ../../dev/usb

KMOD=	slhci
SRCS=	sl811hs.c slhci_pccard.c

SRCS+= opt_slhci.h opt_usb.h device_if.h bus_if.h usbdevs.h card_if.h power_if.h pccarddevs.h

.include <bsd.kmod.mk>
