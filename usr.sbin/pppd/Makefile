# $FreeBSD: src/usr.sbin/pppd/Makefile,v 1.30 2006/03/17 18:54:42 ru Exp $

.include <bsd.own.mk>

# I once used this extensively, but no longer have a modem.  Feel free
# to ask me questions about it, but I disclaim ownership now.  -Peter

PROG=	pppd
MAN=	pppd.8
SRCS=	main.c magic.c fsm.c lcp.c ipcp.c ipxcp.c upap.c chap.c ccp.c \
	demand.c auth.c options.c sys-bsd.c
BINMODE=4550
BINOWN=	root
BINGRP=	dialer

CFLAGS+= -DHAVE_PATHS_H

DPADD=	${LIBCRYPT} ${LIBUTIL} ${LIBMD}
LDADD=	-lcrypt -lutil -lmd

# Support SPX/IPX - not quite ready
#CFLAGS+= -DIPX_CHANGE
#SRCS+=	ipxcp.c

# Callback Control Protocol
CFLAGS+= -DCBCP_SUPPORT
SRCS+=	cbcp.c

# Filter support
CFLAGS+= -DPPP_FILTER
DPADD+=	${LIBPCAP}
LDADD+=	-lpcap

# MS-CHAP support.  Requires the DES library.
.if ${MK_OPENSSL} != "no" && !defined(RELEASE_CRUNCH)
CFLAGS+= -DCHAPMS
SRCS+=	chap_ms.c
LDADD+=	-lcrypto
DPADD+=	${LIBCRYPTO}
.endif

.if defined(RELEASE_CRUNCH)
# We must create these objects because crunchgen will link them,
# and we don't want any unused symbols to spoil the final link.
SRCS+= chap_ms.c
chap_ms.o:
	>null_${.PREFIX}.c
	cc -c -o ${.TARGET} null_${.PREFIX}.c
.endif

.include <bsd.prog.mk>
