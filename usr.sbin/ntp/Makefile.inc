# $FreeBSD: src/usr.sbin/ntp/Makefile.inc,v 1.9 2006/03/17 18:54:41 ru Exp $

.include <bsd.own.mk>

DEFS_LOCAL= -DPARSE -DHAVE_CONFIG_H
NTPDEFS=   -DSYS_FREEBSD
# CLOCKDEFS=
#	-DLOCAL_CLOCK -DPST -DWWVB -DAS2201 -DGOES -DGPSTM -DOMEGA \
#	-DLEITCH -DTRAK -DACTS -DATOM -DDATUM -DHEATH -DMSFEES \
#	-DMX4200 -DNMEA -DBOEDER
CFLAGS+= ${NTPDEFS} ${DEFS_LOCAL} ${CLOCKDEFS}

.if ${MK_OPENSSL} != "no" && !defined(RELEASE_CRUNCH)
CFLAGS+= -DOPENSSL
.endif

LIBPARSE=	${.OBJDIR}/../libparse/libparse.a
LIBNTP=	${.OBJDIR}/../libntp/libntp.a

.include "../Makefile.inc"
