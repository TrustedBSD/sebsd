# $Id$
# $FreeBSD: src/usr.bin/bluetooth/rfcomm_sppd/Makefile,v 1.3 2005/01/28 16:08:07 ru Exp $

PROG=		rfcomm_sppd
SRCS=		rfcomm_sppd.c rfcomm_sdp.c
WARNS?=		2

DPADD=		${LIBBLUETOOTH} ${LIBSDP}
LDADD=		-lbluetooth -lsdp

.include <bsd.prog.mk>
