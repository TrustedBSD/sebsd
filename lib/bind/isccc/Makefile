# $FreeBSD: src/lib/bind/isccc/Makefile,v 1.6 2006/03/17 18:54:25 ru Exp $

.include <bsd.own.mk>

BIND_DIR=	${.CURDIR}/../../../contrib/bind9
LIB_BIND_REL=	..
LIB_BIND_DIR=	${.CURDIR}/${LIB_BIND_REL}
SRCDIR=		${BIND_DIR}/lib/isccc

.include	"${LIB_BIND_DIR}/config.mk"

LIB=		isccc

.PATH:		${SRCDIR}
SRCS=		alist.c base64.c cc.c ccmsg.c \
		lib.c \
		result.c sexpr.c symtab.c version.c

CFLAGS+=	-I${SRCDIR}/include

.if ${MK_BIND_LIBS} != "no"
INCS=		${SRCDIR}/include/isccc/alist.h \
		${SRCDIR}/include/isccc/base64.h \
		${SRCDIR}/include/isccc/cc.h \
		${SRCDIR}/include/isccc/ccmsg.h \
		${SRCDIR}/include/isccc/events.h \
		${SRCDIR}/include/isccc/lib.h \
		${SRCDIR}/include/isccc/result.h \
		${SRCDIR}/include/isccc/sexpr.h \
		${SRCDIR}/include/isccc/symtab.h \
		${SRCDIR}/include/isccc/symtype.h \
		${SRCDIR}/include/isccc/types.h \
		${SRCDIR}/include/isccc/util.h \
		${SRCDIR}/include/isccc/version.h

INCSDIR=	${INCLUDEDIR}/isccc
.endif

.include <bsd.lib.mk>
