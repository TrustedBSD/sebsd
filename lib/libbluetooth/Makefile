# $Id$
# $FreeBSD: src/lib/libbluetooth/Makefile,v 1.2 2005/07/22 17:18:59 kensmith Exp $

LIB=		bluetooth
MAN=		bluetooth.3

WARNS?=		2
CFLAGS+=	-I${.CURDIR} -I${.CURDIR}/../../sys

SHLIB_MAJOR=	2

SRCS=		bluetooth.c
INCS=		bluetooth.h

MLINKS+=	bluetooth.3 bt_gethostbyname.3
MLINKS+=	bluetooth.3 bt_gethostbyaddr.3
MLINKS+=	bluetooth.3 bt_gethostent.3
MLINKS+=	bluetooth.3 bt_sethostent.3
MLINKS+=	bluetooth.3 bt_endhostent.3

MLINKS+=	bluetooth.3 bt_getprotobyname.3
MLINKS+=	bluetooth.3 bt_getprotobynumber.3
MLINKS+=	bluetooth.3 bt_getprotoent.3
MLINKS+=	bluetooth.3 bt_setprotoent.3
MLINKS+=	bluetooth.3 bt_endprotoent.3

MLINKS+=	bluetooth.3 bt_ntoa.3
MLINKS+=	bluetooth.3 bt_aton.3

.include <bsd.lib.mk>
