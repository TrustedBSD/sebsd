# $FreeBSD: src/sys/modules/if_vlan/Makefile,v 1.4 2006/02/17 10:52:59 ru Exp $

.PATH: ${.CURDIR}/../../net

KMOD=	if_vlan
SRCS=	if_vlan.c
SRCS+=	opt_inet.h opt_vlan.h

.if !defined(KERNBUILDDIR)
opt_inet.h:
	echo "#define INET 1" > ${.TARGET}
.endif

.include <bsd.kmod.mk>
