#	@(#)Makefile	8.2 (Berkeley) 9/21/96
# $FreeBSD: src/usr.sbin/praliases/Makefile,v 1.11 2005/06/10 06:12:53 des Exp $

SENDMAIL_DIR=	${.CURDIR}/../../contrib/sendmail
.PATH: ${SENDMAIL_DIR}/praliases

PROG=	praliases
SRCS=	praliases.c
MAN=	praliases.8

CFLAGS+= -I${SENDMAIL_DIR}/src -I${SENDMAIL_DIR}/include -I.
CFLAGS+= -DNEWDB -DNOT_SENDMAIL

LIBSMDIR=	${.OBJDIR}/../../lib/libsm
LIBSM=		${LIBSMDIR}/libsm.a

LIBSMDBDIR=	${.OBJDIR}/../../lib/libsmdb
LIBSMDB=	${LIBSMDBDIR}/libsmdb.a

LIBSMUTILDIR=	${.OBJDIR}/../../lib/libsmutil
LIBSMUTIL=	${LIBSMUTILDIR}/libsmutil.a

DPADD=	${LIBSMDB} ${LIBSMUTIL} ${LIBSM}
LDADD=	${LIBSMDB} ${LIBSMUTIL} ${LIBSM}

SRCS+=	sm_os.h
CLEANFILES+=sm_os.h

# User customizations to the sendmail build environment
CFLAGS+= ${SENDMAIL_CFLAGS}
LDFLAGS+=${SENDMAIL_LDFLAGS}
DPADD+=	${SENDMAIL_DPADD}
LDADD+=	${SENDMAIL_LDADD}

sm_os.h:
	ln -sf ${SENDMAIL_DIR}/include/sm/os/sm_os_freebsd.h sm_os.h

.include <bsd.prog.mk>
