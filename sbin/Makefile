#	@(#)Makefile	8.5 (Berkeley) 3/31/94
# $FreeBSD: src/sbin/Makefile,v 1.159 2006/03/17 18:54:30 ru Exp $

.include <bsd.own.mk>

# XXX MISSING:		icheck ncheck

SUBDIR=	adjkerntz \
	atacontrol \
	${_atm} \
	badsect \
	bsdlabel \
	camcontrol \
	ccdconfig \
	clri \
	comcontrol \
	conscontrol \
	${_devd} \
	devfs \
	dhclient \
	dmesg \
	dump \
	dumpfs \
	dumpon \
	${_fdisk} \
	${_fdisk_pc98} \
	ffsinfo \
	fsck \
	fsck_ffs \
	fsck_msdosfs \
	fsdb \
	fsirand \
	gbde \
	geom \
	ggate \
	gpt \
	growfs \
	gvinum \
	ifconfig \
	init \
	${_ip6fw} \
	${_ipf} \
	ipfw \
	kldconfig \
	kldload \
	kldstat \
	kldunload \
	ldconfig \
	${_mca} \
	md5 \
	mdconfig \
	mdmfs \
	mknod \
	mksnap_ffs \
	mount \
	mount_cd9660 \
	mount_ext2fs \
	mount_msdosfs \
	mount_nfs \
	mount_nfs4 \
	mount_ntfs \
	mount_nullfs \
	mount_reiserfs \
	mount_std \
	mount_udf \
	mount_umapfs \
	mount_unionfs \
	natd \
	newfs \
	newfs_msdos \
	nfsiod \
	nos-tun \
	${_pfctl} \
	${_pflogd} \
	ping \
	${_ping6} \
	quotacheck \
	rcorder \
	reboot \
	restore \
	${_restorecon} \
	route \
	routed \
	rtsol \
	savecore \
	${_sconfig} \
	setfsmac \
	setkey \
	shutdown \
	slattach \
	spppcontrol \
	startslip \
	sunlabel \
	swapon \
	sysctl \
	tunefs \
	umount \

.if ${MK_ATM} != "no"
_atm=		atm
.endif

.if ${MK_CXX} != "no"
_devd=		devd
.endif

.if ${MK_IPFILTER} != "no"
_ipf=		ipf
.endif

.if ${MK_PF} != "no"
_pfctl=		pfctl
_pflogd=	pflogd
.endif

.if ${MK_INET6} != "no"
_ip6fw=		ip6fw
_ping6=		ping6
.endif

.if !defined(NO_SEBSD)
_restorecon=	restorecon
.endif

.if ${MACHINE_ARCH} == "i386"
.if ${MACHINE} == "i386"
_fdisk=		fdisk
.elif ${MACHINE} == "pc98"
_fdisk_pc98=	fdisk_pc98
.endif
_sconfig=	sconfig
.endif

.if ${MACHINE_ARCH} == "amd64"
_fdisk=		fdisk
.endif

.if ${MACHINE_ARCH} == "arm"
_fdisk=		fdisk
.endif

.if ${MACHINE_ARCH} == "ia64"
_fdisk=		fdisk
_mca=		mca
.endif

.include <bsd.subdir.mk>
