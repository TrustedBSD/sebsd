# $FreeBSD: src/sys/modules/sppp/Makefile,v 1.7 2005/10/14 23:30:15 yar Exp $

.PATH: ${.CURDIR}/../../net

KMOD=	sppp
SRCS=	if_spppfr.c if_spppsubr.c slcompress.c
SRCS+=	opt_inet.h opt_inet6.h opt_ipx.h opt_mac.h

EXPORT_SYMS=	sppp_attach	\
		sppp_detach	\
		sppp_input	\
		sppp_ioctl	\
		sppp_dequeue	\
		sppp_pick	\
		sppp_isempty	\
		sppp_flush

.if !defined(KERNBUILDDIR)
opt_inet.h:
	echo "#define INET 1" > opt_inet.h

opt_inet6.h:
	echo "#define INET6 1" > opt_inet6.h

opt_ipx.h:
	echo "#define IPX 1" > opt_ipx.h
.endif

.include <bsd.kmod.mk>
