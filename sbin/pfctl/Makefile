# $FreeBSD: src/sbin/pfctl/Makefile,v 1.5 2005/05/03 16:57:38 mlaier Exp $

.PATH:	${.CURDIR}/../../contrib/pf/pfctl
.PATH:	${.CURDIR}/../../contrib/pf/man

PROG=	pfctl
MAN=	pfctl.8 pf.4 pflog.4 pfsync.4 pf.conf.5 pf.os.5

SRCS = pfctl.c parse.y pfctl_parser.c pf_print_state.c pfctl_altq.c
SRCS+= pfctl_osfp.c pfctl_radix.c pfctl_table.c pfctl_qstats.c
SRCS+= pfctl_optimize.c

CFLAGS+= -Wall -Wmissing-prototypes -Wno-uninitialized
CFLAGS+= -Wstrict-prototypes -I${.CURDIR}/../../contrib/pf/pfctl

# XXX ALTQ
CFLAGS+= -DENABLE_ALTQ
#CFLAGS+= -I${.CURDIR}/missing

YFLAGS=

LDADD+=	-lm -lmd
DPADD+=	${LIBM}

.include <bsd.prog.mk>
