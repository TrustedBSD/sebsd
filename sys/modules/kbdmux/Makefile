# $Id$
# $FreeBSD: src/sys/modules/kbdmux/Makefile,v 1.3 2006/03/01 18:34:48 emax Exp $

.PATH: ${.CURDIR}/../../dev/kbdmux

KMOD=	kbdmux
SRCS=	kbdmux.c opt_kbd.h bus_if.h device_if.h

.if !defined(KERNBUILDDIR)
opt_kbd.h:
	echo "#define KBD_INSTALL_CDEV 1" > ${.TARGET}
.endif

.include <bsd.kmod.mk>
