# $FreeBSD: src/sys/modules/myri10ge/myri10ge_ethp_z8e/Makefile,v 1.1 2006/02/19 22:39:19 gallatin Exp $

MYRI10GE= ${.CURDIR}/../../../dev/myri10ge
.PATH= ${MYRI10GE}
KMOD=	myri10ge_ethp_z8e
FIRMWS=	ethp_z8e.dat:myri10ge_ethp_z8e
CLEANFILES+= ethp_z8e.dat

ethp_z8e.dat: ${MYRI10GE}/ethp_z8e.dat.gz.uu
	uudecode -p < ${MYRI10GE}/ethp_z8e.dat.gz.uu \
		| gzip -dc > ${.TARGET}

.include <bsd.kmod.mk>
