#
# $FreeBSD: $
#

.PATH: ${.CURDIR} ${.CURDIR}/../../contrib/sebsd/libsepol/src
.PATH: ${.CURDIR}/../../contrib/sebsd/libsepol/include
.PATH: ${.CURDIR}/../../contrib/sebsd/libsepol/man/man3

MAINTAINER= cboss@nai.com
LIB= sepol
CFLAGS+= -g -I${.CURDIR}/../../contrib/sebsd/libsepol/include

SRCS=	assertion.c avrule_block.c avtab.c boolean_record.c booleans.c \
	conditional.c constraint.c context.c context_record.c debug.c \
	ebitmap.c expand.c genbools.c genusers.c handle.c hashtab.c \
	hierarchy.c iface_record.c interfaces.c link.c mls.c module.c \
	node_record.c nodes.c policydb.c policydb_convert.c \
	policydb_public.c port_record.c ports.c roles.c services.c \
	sidtab.c symtab.c user_record.c users.c util.c write.c

INCSDIR=${INCLUDEDIR}/sepol

INCS=	sepol/boolean_record.h sepol/booleans.h sepol/context.h \
	sepol/context_record.h sepol/debug.h sepol/handle.h \
	sepol/iface_record.h sepol/interfaces.h sepol/module.h \
	sepol/node_record.h sepol/nodes.h sepol/policydb.h \
	sepol/port_record.h sepol/ports.h sepol/roles.h sepol/sepol.h \
	sepol/user_record.h sepol/users.h

MAN=	sepol_check_context.3 sepol_genbools.3 sepol_genusers.3  

.include <bsd.lib.mk>
