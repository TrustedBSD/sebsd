#	@(#)Makefile	8.1 (Berkeley) 6/4/93
# $FreeBSD: src/libexec/Makefile,v 1.76 2006/03/17 18:54:28 ru Exp $

.include <bsd.own.mk>

SUBDIR=	atrun \
	bootpd \
	comsat \
	fingerd \
	ftpd \
	${_ftp-proxy} \
	getty \
	lukemftpd \
	${_mail.local} \
	makekey \
	${_mknetid} \
	pppoed \
	pt_chown \
	rbootd \
	revnetgroup \
	${_rlogind} \
	rpc.rquotad \
	rpc.rstatd \
	rpc.rusersd \
	rpc.rwalld \
	rpc.sprayd \
	${_rshd} \
	${_rtld-elf} \
	save-entropy \
	${_smrsh} \
	talkd \
	tcpd \
	telnetd \
	tftpd \
	${_ypxfr}

.if ${MK_NIS} != "no"
_mknetid=	mknetid
_ypxfr=		ypxfr
.endif

.if ${MK_PF} != "no"
_ftp-proxy=	ftp-proxy
.endif

.if !defined(NO_PIC)
_rtld-elf=	rtld-elf
.endif

.if ${MK_RCMDS} != "no"
_rlogind=	rlogind
_rshd=		rshd
.endif

.if ${MK_SENDMAIL} != "no"
_mail.local=	mail.local
_smrsh=	smrsh
.endif

.include <bsd.subdir.mk>
