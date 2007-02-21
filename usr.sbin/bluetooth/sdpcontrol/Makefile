# $Id$
# $FreeBSD: src/usr.sbin/bluetooth/sdpcontrol/Makefile,v 1.1 2003/10/12 22:04:24 emax Exp $

PROG=		sdpcontrol
MAN=		sdpcontrol.8
SRCS=		sdpcontrol.c search.c
WARNS?=		2

DPADD=		${LIBBLUETOOTH} ${LIBSDP}
LDADD=		-lbluetooth -lsdp

.include <bsd.prog.mk>
