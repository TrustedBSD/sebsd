# $FreeBSD: src/gnu/usr.bin/gdb/kgdb/Makefile,v 1.6 2005/02/20 23:06:03 kan Exp $

PROG=	kgdb${GDB_SUFFIX}
SRCS=	main.c kthr.c trgt.c trgt_${TARGET_ARCH}.c
WARNS?=	2

BULIBS= ${OBJ_BU}/libbfd/libbfd.a ${OBJ_BU}/libopcodes/libopcodes.a \
	${OBJ_BU}/libiberty/libiberty.a
GDBLIBS= ${OBJ_GDB}/libgdb/libgdb.a

DPADD=	${GDBLIBS} ${BULIBS} ${LIBKVM} ${LIBM} ${LIBREADLINE} ${LIBTERMCAP} ${LIBGNUREGEX}
LDADD=	${GDBLIBS} ${BULIBS} -lkvm -lm -lreadline -ltermcap -lgnuregex

.include <bsd.prog.mk>
