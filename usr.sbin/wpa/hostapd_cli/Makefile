# $FreeBSD: src/usr.sbin/wpa/hostapd_cli/Makefile,v 1.3 2006/03/07 05:54:20 sam Exp $

CONTRIB=	${.CURDIR}/../../../contrib
HOSTAPD_DISTDIR?= ${CONTRIB}/hostapd
WPA_SUPPLICANT_DISTDIR?= ${CONTRIB}/wpa_supplicant

.PATH: ${HOSTAPD_DISTDIR} ${WPA_SUPPLICANT_DISTDIR}

PROG=	hostapd_cli
SRCS=	hostapd_cli.c wpa_ctrl.c

MAN=	hostapd_cli.8

.include <bsd.prog.mk>
