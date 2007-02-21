# $FreeBSD: src/sbin/ggate/Makefile,v 1.3 2006/03/17 18:54:31 ru Exp $

.include <bsd.own.mk>

SUBDIR=	${_ggatec} \
	${_ggated} \
	ggatel

.if ${MK_LIBPTHREAD} != "no"
_ggatec=	ggatec
_ggated=	ggated
.endif

.include <bsd.subdir.mk>
