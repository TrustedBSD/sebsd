# $FreeBSD: src/lib/libncp/Makefile,v 1.8 2006/03/16 15:18:16 ru Exp $

LIB=		ncp

SHLIB_MAJOR=	2

DPADD=		${LIBIPX}
LDADD=		-lipx

SRCS=	ncpl_subr.c ncpl_bind.c ncpl_queue.c ncpl_file.c ncpl_misc.c \
	ncpl_net.c ncpl_rcfile.c ncpl_conn.c ncpl_nls.c ncpl_msg.c \
	ncpl_rpc.c ncpl_crypt.c ipx.c sap.c

.include <bsd.lib.mk>
