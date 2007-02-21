# $FreeBSD: $

.PATH:	${.CURDIR}/../../contrib/sebsd/checkpolicy

PROG=	checkmodule
MAN=	
SRCS= policy_scan.l policy_parse.y checkmodule.c queue.c module_compiler.c \
      parse_util.c
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/checkpolicy
CFLAGS+=-I${.CURDIR}/../../contrib/sebsd/libsepol/include
CFLAGS+=-I${.CURDIR}/../../sys
CFLAGS+=-I${.OBJDIR}

LDADD=	-ll -lsepol -lsecompat
DPADD=	${LIBL} ${LIBSEPOL} ${LIBSECOMPAT}

WARNS=	0

MAINTAINER=	cboss@tislabs.com

.include <bsd.prog.mk>
