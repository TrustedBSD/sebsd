# $Id$
# $FreeBSD: src/sys/modules/vkbd/Makefile,v 1.3 2005/10/14 23:30:16 yar Exp $

.PATH:	${.CURDIR}/../../dev/vkbd

KMOD=	vkbd
SRCS=	vkbd.c opt_kbd.h

.if !defined(KERNBUILDDIR)
opt_kbd.h:
	echo "#define KBD_INSTALL_CDEV 1" > ${.TARGET}
.endif

.include <bsd.kmod.mk>
