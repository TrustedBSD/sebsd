# $FreeBSD: src/gnu/usr.bin/binutils/strings/Makefile,v 1.12 2004/06/16 07:09:44 obrien Exp $

.include "../Makefile.inc0"

.PATH: ${SRCDIR}/binutils ${SRCDIR}/binutils/doc

PROG=	strings
SRCS=	strings.c
WARNS?=	2
CFLAGS+= -D_GNU_SOURCE
CFLAGS+= -I${.CURDIR}/${RELTOP}/libbinutils
CFLAGS+= -I${SRCDIR}/binutils
DPADD=	${RELTOP}/libbinutils/libbinutils.a
DPADD+=	${RELTOP}/libbfd/libbfd.a
DPADD+=	${RELTOP}/libiberty/libiberty.a
LDADD=	${DPADD}

.include <bsd.prog.mk>
