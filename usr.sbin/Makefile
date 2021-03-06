#	From: @(#)Makefile	5.20 (Berkeley) 6/12/93
# $FreeBSD: src/usr.sbin/Makefile,v 1.348 2006/03/20 14:24:58 ru Exp $

.include <bsd.own.mk>

# XXX MISSING:		mkproto
SUBDIR=	ac \
	accton \
	${_acpi} \
	adduser \
	amd \
	ancontrol \
	${_apm} \
	${_apmd} \
	${_arlcontrol} \
	arp \
	${_audit} \
	${_auditd} \
	${_auditreduce} \
	${_asf} \
	${_atm} \
	${_authpf} \
	${_bluetooth} \
	${_boot0cfg} \
	${_boot98cfg} \
	bootparamd \
	bsnmpd \
	${_btxld} \
	burncd \
	cdcontrol \
	chkgrp \
	chown \
	chroot \
	ckdist \
	config \
	cron \
	crunch \
	ctm \
	daemon \
	dconschat \
	devinfo \
	digictl \
	diskinfo \
	${_dnssec-keygen} \
	${_dnssec-signzone} \
	${_editmap} \
	edquota \
	${_eeprom} \
	${_elf2exe} \
	extattr \
	extattrctl \
	faithd \
	fdcontrol \
	fdformat \
	fdread \
	fdwrite \
	flowctl \
	fwcontrol \
	getfhash \
	getfmac \
	getpmac \
	gstat \
	${_i4b} \
	ifmcstat \
	inetd \
	iostat \
	ip6addrctl \
	ipfwpcap \
	${_IPXrouted} \
	jail \
	jexec \
	jls \
	kbdcontrol \
	kbdmap \
	${_keyserv} \
	${_kgmon} \
	${_kgzip} \
	kldxref \
	lastlogin \
	${_lpr} \
	${_lptcontrol} \
	lmcconfig \
	${_mailstats} \
	mailwrapper \
	${_makemap} \
	manctl \
	memcontrol \
	mergemaster \
	mixer \
	${_mld6query} \
	mlxcontrol \
	mountd \
	${_mount_nwfs} \
	mount_portalfs \
	${_mount_smbfs} \
	moused \
	${_mptable} \
	mrouted \
	mtest \
	mtree \
	${_named} \
	${_named-checkconf} \
	${_named-checkzone} \
	${_named.reload} \
	${_ndiscvt} \
	ndp \
	newsyslog \
	nfsd \
	ngctl \
	nghook \
	nologin \
	ntp \
	${_ofwdump} \
	${_pccard} \
	pciconf \
	${_pcvt} \
	periodic \
	pkg_install \
	pmccontrol \
	pmcstat \
	${_pnpinfo} \
	portsnap \
	powerd \
	ppp \
	${_pppctl} \
	pppd \
	pppstats \
	${_praliases} \
	${_praudit} \
	procctl \
	pstat \
	pw \
	pwd_mkdb \
	quot \
	quotaon \
	rarpd \
	raycontrol \
	repquota \
	${_rip6query} \
	rmt \
	${_rndc} \
	${_rndc-confgen} \
	${_route6d} \
	rpcbind \
	rpc.lockd \
	rpc.statd \
	rpc.umntall \
	${_rpc.yppasswdd} \
	${_rpc.ypupdated} \
	${_rpc.ypxfrd} \
	rrenumd \
	rtadvd \
	rtprio \
	rtsold \
	rwhod \
	sa \
	${_sendmail} \
	${_avcstat}\
	${_genhomedircon}\
	${_load_policy} \
	${_newrole} \
	${_setfiles} \
	${_setsebool} \
	${_semodule} \
	${_semodule_expand} \
	${_semodule_link} \
	${_semodule_package} \
	setpmac \
	${_sicontrol} \
	sliplogin \
	slstat \
	smbmsg \
	snapinfo \
	${_spkrtest} \
	spray \
	${_sysinstall} \
	syslogd \
	tcpdchk \
	tcpdmatch \
	tcpdrop \
	tcpdump \
	timed \
	traceroute \
	${_traceroute6} \
	trpt \
	tzsetup \
	ugidfw \
	${_usbdevs} \
	vidcontrol \
	vipw \
	vnconfig \
	watch \
	watchdogd \
	wicontrol \
	${_wlconfig} \
	wpa \
	${_ypbind} \
	${_yp_mkdb} \
	${_yppoll} \
	${_yppush} \
	${_ypserv} \
	${_ypset} \
	zic \
	${_zzz}

.if ${MACHINE_ARCH} != "arm"
_sysinstall=	sysinstall
.endif

.if ${MK_ATM} != "no"
_atm=		atm
.endif

.if ${MK_AUDIT} != "no"
_audit= 	audit
_auditd=	auditd
_auditreduce=	auditreduce
_praudit=	praudit
.endif

.if ${MK_BIND_DNSSEC} != "no" && ${MK_OPENSSL} != "no"
_dnssec-keygen=		dnssec-keygen
_dnssec-signzone=	dnssec-signzone
.endif
.if ${MK_BIND_NAMED} != "no"
_named=			named
_named-checkconf=	named-checkconf
_named-checkzone=	named-checkzone
_named.reload=		named.reload
_rndc=			rndc
_rndc-confgen=		rndc-confgen
.endif

.if ${MK_BLUETOOTH} != "no"
_bluetooth=	bluetooth
.endif

.if ${MK_OPENSSL} != "no"
_keyserv=	keyserv
.endif

.if ${MK_INET6} != "no"
_mld6query=	mld6query
_rip6query=	rip6query
_route6d=	route6d
_traceroute6=	traceroute6
.endif

.if ${MK_IPX} != "no"
_IPXrouted=	IPXrouted
.endif

.if ${MK_NIS} != "no"
_rpc.yppasswdd=	rpc.yppasswdd
_rpc.ypupdated=	rpc.ypupdated
_rpc.ypxfrd=	rpc.ypxfrd
_ypbind=	ypbind
_yp_mkdb=	yp_mkdb
_yppoll=	yppoll
_yppush=	yppush
_ypserv=	ypserv
_ypset=		ypset
.endif

.if ${MK_AUTHPF} != "no"
_authpf=	authpf
.endif

.if ${MK_LPR} != "no"
_lpr=		lpr
.endif

.if !defined(NO_SEBSD)
_avcstat=	   avcstat
_genhomedircon=	   genhomedircon
_load_policy=	   load_policy
_newrole=	   newrole
_setfiles=         setfiles
_setsebool=        setsebool
_semodule=         semodule
_semodule_expand=  semodule_expand
_semodule_link=    semodule_link
_semodule_package= semodule_package
.endif

.if ${MK_SENDMAIL} != "no"
_editmap=	editmap
_mailstats=	mailstats
_makemap=	makemap
_praliases=	praliases
_sendmail=	sendmail
.endif

.if ${MK_USB} != "no"
_usbdevs=	usbdevs
.endif

.if ${MACHINE_ARCH} == "arm"
_kgmon=		kgmon
.endif

.if ${MACHINE_ARCH} == "i386"
_apm=		apm
_apmd=		apmd
_asf=		asf
_btxld=		btxld
.if ${MK_I4B} != "no"
_i4b=		i4b
.endif
_kgmon=		kgmon
_kgzip=		kgzip
_lptcontrol=	lptcontrol
.if ${MK_NCP} != "no"
_mount_nwfs=	mount_nwfs
.endif
_mount_smbfs=	mount_smbfs
_mptable=	mptable
_ndiscvt=	ndiscvt
_pccard=	pccard
_pnpinfo=	pnpinfo
.if ${MK_LIBPTHREAD} != "no"
_pppctl=	pppctl
.endif
_sicontrol=	sicontrol
_spkrtest=	spkrtest
_zzz=		zzz
.if ${MACHINE} == "i386" 
.if ${MK_ACPI} != "no"
_acpi=		acpi
.endif
_arlcontrol=	arlcontrol
_boot0cfg=	boot0cfg
.if ${MK_PCVT} != "no"
_pcvt=		pcvt
.endif
_wlconfig=	wlconfig
.elif ${MACHINE} == "pc98"
_boot98cfg=	boot98cfg
.endif
.endif

.if ${MACHINE_ARCH} == "alpha"
_elf2exe=	elf2exe
_pnpinfo=	pnpinfo
.if ${MK_LIBC_R} != "no"
_pppctl=	pppctl
.endif
.endif

# kgzip: builds, but missing support files
# mptable: broken (not 64 bit clean)
# pnpinfo: crashes (not really useful anyway)
.if ${MACHINE_ARCH} == "amd64"
.if ${MK_ACPI} != "no"
_acpi=		acpi
.endif
_asf=		asf
_boot0cfg=	boot0cfg
_btxld=		btxld
_kgmon=		kgmon
_lptcontrol=	lptcontrol
.if ${MK_NCP} != "no"
_mount_nwfs=	mount_nwfs
.endif
_mount_smbfs=	mount_smbfs
_mptable=	mptable
_ndiscvt=	ndiscvt
.if ${MK_LIBPTHREAD} != "no"
_pppctl=	pppctl
.endif
_sicontrol=	sicontrol
_spkrtest=	spkrtest
_zzz=		zzz
.endif

.if ${MACHINE_ARCH} == "ia64"
.if ${MK_ACPI} != "no"
_acpi=		acpi
.endif
_kgmon=		kgmon
.if ${MK_LIBPTHREAD} != "no"
_pppctl=	pppctl
.endif
_zzz=		zzz
.endif

.if ${MACHINE_ARCH} == "powerpc"
_mount_smbfs=	mount_smbfs
.endif

.if ${MACHINE_ARCH} == "sparc64"
_eeprom=	eeprom
_ofwdump=	ofwdump
.if ${MK_LIBC_R} != "no"
_pppctl=	pppctl
.endif
.endif

.include <bsd.subdir.mk>
