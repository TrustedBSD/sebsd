# $FreeBSD: src/gnu/lib/libobjc/Makefile,v 1.29 2006/03/16 15:18:15 ru Exp $

OBJCDIR=${.CURDIR}/../../../contrib/libobjc
GCCDIR=	${.CURDIR}/../../../contrib/gcc

.PATH: ${OBJCDIR}/objc ${OBJCDIR}

LIB=		objc
SHLIB_MAJOR=	2

SRCS=   archive.c class.c encoding.c gc.c hash.c init.c misc.c \
	nil_method.c objects.c sarray.c selector.c sendmsg.c \
	thr.c thr-posix.c \
	NXConstStr.m Object.m Protocol.m linking.m

INCS=	encoding.h hash.h objc-api.h objc-list.h objc.h runtime.h \
	sarray.h thr.h typedstream.h NXConstStr.h Object.h Protocol.h
INCSDIR=${INCLUDEDIR}/objc

OBJCFLAGS= -fgnu-runtime ${CFLAGS}
CFLAGS+= -DHAVE_GTHR_DEFAULT -DIN_GCC -DIN_TARGET_LIBS
CFLAGS+= -I. -I${.CURDIR}/../../usr.bin/cc/cc_tools
CFLAGS+= -I${OBJCDIR}/objc -I${OBJCDIR} 
CFLAGS+= -I${GCCDIR}/config -I${GCCDIR}
CFLAGS+= -frandom-seed=RepeatabilityConsideredGood

GENHDRS=	runtime-info.h tconfig.h tm.h
CLEANFILES+=	${GENHDRS}
SRCS+=		${GENHDRS}

${OBJS}: ${GENHDRS}

runtime-info.h:
	`${CC} --print-prog-name=cc1obj` -print-objc-runtime-info \
	    < /dev/null > ${.TARGET}

tconfig.h tm.h : ${.CURDIR}/../../usr.bin/cc/cc_tools/Makefile
	${MAKE} -f ${.ALLSRC} MFILE=${.ALLSRC} GCCDIR=${GCCDIR} ${.TARGET}

.include <bsd.lib.mk>
