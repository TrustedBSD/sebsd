# $FreeBSD: src/usr.sbin/cron/cron/Makefile,v 1.15 2001/07/20 06:19:40 obrien Exp $

PROG=	cron
MAN=	cron.8
SRCS=	cron.c database.c do_command.c job.c user.c popen.c

CFLAGS+= -DLOGIN_CAP

DPADD=	${LIBCRON} ${LIBUTIL}
LDADD=	${LIBCRON} -lutil

.if !defined(NO_SEBSD)
CFLAGS+= -I${.CURDIR}/../../../sys
CFLAGS+= -DSEBSD
DPADD+=	${LIBSELINUX}
LDADD+=	-lselinux -lsepol -lsecompat
.endif

.include <bsd.prog.mk>
