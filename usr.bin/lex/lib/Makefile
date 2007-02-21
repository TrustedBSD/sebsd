# $FreeBSD: src/usr.bin/lex/lib/Makefile,v 1.10 2006/03/18 21:37:05 ru Exp $

.include <bsd.own.mk>

LIB=    ln
SRCS=   libmain.c libyywrap.c
NO_PIC=

LINKS=  ${LIBDIR}/libln.a ${LIBDIR}/libl.a
LINKS+=	${LIBDIR}/libln.a ${LIBDIR}/libfl.a

.if ${MK_PROFILE} != "no"
LINKS+= ${LIBDIR}/libln_p.a ${LIBDIR}/libl_p.a
LINKS+=	${LIBDIR}/libln_p.a ${LIBDIR}/libfl_p.a
.endif

.include <bsd.lib.mk>

