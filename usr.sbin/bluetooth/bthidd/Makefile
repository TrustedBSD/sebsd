# $Id$
# $FreeBSD: src/usr.sbin/bluetooth/bthidd/Makefile,v 1.5 2006/03/15 10:46:38 ru Exp $

PROG=		bthidd
#MAN=		bthidd.8 bthidd.conf.5
NO_MAN=
SRCS=		bthidd.c client.c hid.c kbd.c lexer.l parser.y server.c \
		session.c

CFLAGS+=	-I${.CURDIR}
WARNS?=		2
DEBUG_FLAGS=	-g

DPADD=          ${LIBBLUETOOTH} ${LIBSDP}
LDADD=		-lbluetooth -lusbhid

.include <bsd.prog.mk>
