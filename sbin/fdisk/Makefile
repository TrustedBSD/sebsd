# $FreeBSD: src/sbin/fdisk/Makefile,v 1.12 2005/07/15 08:02:51 phk Exp $

PROG=	fdisk
SRCS=	fdisk.c geom_mbr_enc.c
WARNS?=	4
MAN=	fdisk.8

.PATH:	${.CURDIR}/../../sys/geom

DPADD	+=	${LIBGEOM}
LDADD	+=	-lgeom

.include <bsd.prog.mk>

test:	${PROG}
	sh ${.CURDIR}/runtest.sh
