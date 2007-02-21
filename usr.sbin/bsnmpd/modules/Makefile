# $FreeBSD: src/usr.sbin/bsnmpd/modules/Makefile,v 1.12 2006/03/17 18:54:40 ru Exp $

.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../../contrib/bsnmp/snmpd

.if ${MK_ATM} != "no"
_snmp_atm= snmp_atm
.endif

SUBDIR=	${_snmp_atm} \
	snmp_hostres \
	snmp_mibII \
	snmp_netgraph \
	snmp_pf

INCS=	snmpmod.h
INCSDIR= ${INCLUDEDIR}/bsnmp

.include <bsd.prog.mk>
