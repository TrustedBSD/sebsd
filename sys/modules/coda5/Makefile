# $FreeBSD: src/sys/modules/coda5/Makefile,v 1.7 2006/02/27 12:04:13 yar Exp $

.PATH: ${.CURDIR}/../../coda

KMOD=	coda5
SRCS=	vnode_if.h \
	coda_fbsd.c coda_namecache.c coda_psdev.c coda_subr.c \
	coda_venus.c coda_vfsops.c coda_vnops.c \
	opt_coda.h

CFLAGS+= -DCODA5_MODULE

.include <bsd.kmod.mk>
