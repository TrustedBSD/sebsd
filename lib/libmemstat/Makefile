# $FreeBSD: src/lib/libmemstat/Makefile,v 1.5 2005/11/13 13:42:03 rwatson Exp $

WARNS?=		3
LIB=		memstat
SHLIB_MAJOR=	1
DPADD=		${LIBKVM}
LDADD=		-lkvm
SRCS+=		memstat.c
SRCS+=		memstat_all.c
SRCS+=		memstat_malloc.c
SRCS+=		memstat_uma.c
INCS=		memstat.h

MAN=		libmemstat.3

MLINKS+=	libmemstat.3 memstat_mtl_alloc.3
MLINKS+=	libmemstat.3 memstat_mtl_first.3
MLINKS+=	libmemstat.3 memstat_mtl_next.3
MLINKS+=	libmemstat.3 memstat_mtl_find.3
MLINKS+=	libmemstat.3 memstat_mtl_free.3
MLINKS+=	libmemstat.3 memstat_mtl_geterror.3
MLINKS+=	libmemstat.3 memstat_strerror.3
MLINKS+=	libmemstat.3 memstat_sysctl_all.3
MLINKS+=	libmemstat.3 memstat_sysctl_malloc.3
MLINKS+=	libmemstat.3 memstat_sysctl_uma.3
MLINKS+=	libmemstat.3 memstat_kvm_all.3
MLINKS+=	libmemstat.3 memstat_kvm_malloc.3
MLINKS+=	libmemstat.3 memstat_kvm_uma.3

.include <bsd.lib.mk>
