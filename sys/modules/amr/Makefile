# $FreeBSD: src/sys/modules/amr/Makefile,v 1.10 2006/01/25 18:11:59 ambrisko Exp $

.PATH: ${.CURDIR}/../../dev/amr

.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "amd64"
SUBDIR= amr_linux
.endif

KMOD=	amr
SRCS=	amr.c amr_pci.c amr_disk.c device_if.h bus_if.h pci_if.h

# SCSI passthrough support for non-disk devices
#CFLAGS+= -DAMR_SCSI_PASSTHROUGH
SRCS+=	amr_cam.c opt_cam.h opt_scsi.h

# Enable a questionable optimisation for newer adapters
#CFLAGS+= -DAMR_QUARTZ_GOFASTER

# Debugging
#CFLAGS+= -DAMR_DEBUG=3

.include <bsd.kmod.mk>
