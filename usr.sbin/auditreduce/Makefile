#
# $FreeBSD: src/usr.sbin/auditreduce/Makefile,v 1.1 2006/02/02 10:15:30 rwatson Exp $
#

OPENBSMDIR=${.CURDIR}/../../contrib/openbsm
.PATH: ${OPENBSMDIR}/bin/auditreduce

PROG=	auditreduce
MAN=	auditreduce.1

DPADD=	${LIBBSM}
LDADD=	-lbsm

.include <bsd.prog.mk>
