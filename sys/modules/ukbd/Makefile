# $FreeBSD: src/sys/modules/ukbd/Makefile,v 1.21 2005/10/14 23:30:16 yar Exp $

.PATH: ${.CURDIR}/../../dev/usb

KMOD=	ukbd
SRCS=	bus_if.h device_if.h opt_usb.h opt_kbd.h opt_ukbd.h usbdevs.h ukbd.c

.if !defined(KERNBUILDDIR)
opt_kbd.h:
	echo "#define KBD_INSTALL_CDEV 1" > ${.TARGET}
.endif

.include <bsd.kmod.mk>
