# $FreeBSD: src/sys/modules/ipfw/Makefile,v 1.24 2006/03/17 18:54:37 ru Exp $

.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../netinet

KMOD=	ipfw
SRCS=	ip_fw2.c ip_fw_pfil.c
SRCS+=	opt_inet6.h opt_ipsec.h

CFLAGS+= -DIPFIREWALL
#
#If you want it verbose
#CFLAGS+= -DIPFIREWALL_VERBOSE
#CFLAGS+= -DIPFIREWALL_VERBOSE_LIMIT=100
#
#If you want it to pass all packets by default
#CFLAGS+= -DIPFIREWALL_DEFAULT_TO_ACCEPT
#

.if !defined(KERNBUILDDIR)
.if ${MK_INET6_SUPPORT} != "no"
opt_inet6.h:
	echo "#define INET6 1" > ${.TARGET}
.endif
.endif

.include <bsd.kmod.mk>
