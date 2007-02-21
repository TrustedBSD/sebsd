#	$FreeBSD: src/sys/modules/acpi/acpi_video/Makefile,v 1.5 2006/03/16 15:18:16 ru Exp $

.PATH:	${.CURDIR}/../../../dev/acpica

KMOD=	acpi_video
WARNS?=	2
CFLAGS+= -I@/contrib/dev/acpica
SRCS=	acpi_video.c
SRCS+=	opt_acpi.h acpi_if.h bus_if.h device_if.h

.include <bsd.kmod.mk>
