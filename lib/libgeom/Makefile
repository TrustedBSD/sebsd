# $FreeBSD: src/lib/libgeom/Makefile,v 1.10 2004/03/07 16:07:57 phk Exp $

LIB=	geom
SHLIBDIR?= /lib
SRCS+=	geom_getxml.c
SRCS+=	geom_stats.c
SRCS+=	geom_xml2tree.c
SRCS+=	geom_ctl.c
INCS=	libgeom.h

CFLAGS += -I${.CURDIR}

WARNS?=	3

DPADD=	${LIBBSDXML} ${LIBSBUF}
LDADD=	-lbsdxml -lsbuf

MAN=	libgeom.3

MLINKS+= \
	libgeom.3 geom_stats_open.3 \
	libgeom.3 geom_stats_close.3 \
	libgeom.3 geom_stats_resync.3 \
	libgeom.3 geom_stats_snapshot_get.3 \
	libgeom.3 geom_stats_snapshot_free.3 \
	libgeom.3 geom_stats_snapshot_timestamp.3 \
	libgeom.3 geom_stats_snapshot_reset.3 \
	libgeom.3 geom_stats_snapshot_next.3 \
	libgeom.3 gctl_get_handle.3 \
	libgeom.3 gctl_ro_param.3 \
	libgeom.3 gctl_rw_param.3 \
	libgeom.3 gctl_issue.3 \
	libgeom.3 gctl_free.3 \
	libgeom.3 gctl_dump.3

.include <bsd.lib.mk>
