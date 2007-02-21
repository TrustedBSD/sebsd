# $FreeBSD: src/usr.sbin/bsnmpd/modules/Makefile.inc,v 1.12 2005/11/10 10:14:56 harti Exp $

SHLIB_MAJOR=	4
WARNS?=		6

MANFILTER=	sed -e 's%@MODPATH@%${LIBDIR}/%g'		\
		    -e 's%@DEFPATH@%${DEFSDIR}/%g'		\
		    -e 's%@MIBSPATH@%${BMIBSDIR}/%g'
