# $FreeBSD: src/usr.sbin/zic/zdump/Makefile,v 1.10 2003/04/04 17:49:21 obrien Exp $

.PATH: ${.CURDIR}/..

PROG=	zdump
MAN=	${.CURDIR}/../zdump.8
SRCS=	zdump.c ialloc.c scheck.c

CFLAGS+= -DTM_GMTOFF=tm_gmtoff -DTM_ZONE=tm_zone -DSTD_INSPIRED -DPCTS
CFLAGS+= -DHAVE_LONG_DOUBLE -DTZDIR=\"/usr/share/zoneinfo\" -Demkdir=mkdir
CFLAGS+= -I${.CURDIR}/.. -I${.CURDIR}/../../../lib/libc/stdtime

.include <bsd.prog.mk>
