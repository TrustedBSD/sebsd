# $FreeBSD: src/sys/modules/esp/Makefile,v 1.5 2005/05/19 14:51:10 marius Exp $

.PATH: ${.CURDIR}/../../dev/esp ${.CURDIR}/../../sparc64/sbus

KMOD=	esp

SRCS=	ncr53c9x.c
SRCS+=	opt_ddb.h opt_cam.h
SRCS+=	device_if.h bus_if.h

.if ${MACHINE_ARCH} == "sparc64"
SRCS+=	esp_sbus.c ofw_bus_if.h
.endif

.include <bsd.kmod.mk>
