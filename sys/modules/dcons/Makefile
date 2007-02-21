# $Id$
# $FreeBSD: src/sys/modules/dcons/Makefile,v 1.4 2005/10/14 23:30:09 yar Exp $

.PATH:	${.CURDIR}/../../dev/dcons

KMOD	= dcons
SRCS	= dcons.c dcons.h dcons_os.c dcons_os.h \
		opt_dcons.h opt_ddb.h opt_comconsole.h

.if !defined(KERNBUILDDIR)
opt_ddb.h:
	echo "#define KDB 1" > $@

opt_comconsole.h:
	echo "#define ALT_BREAK_TO_DEBUGGER 1" > $@
.endif

CFLAGS+= -I${.CURDIR}/../.. 

.include <bsd.kmod.mk>
