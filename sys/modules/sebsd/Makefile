# $FreeBSD$

.PATH: ${.CURDIR}/../../security/sebsd ${.CURDIR}/../../security/sebsd/avc ${.CURDIR}/../../security/sebsd/ss

KMOD=	sebsd
SRCS=	vnode_if.h \
	opt_mac.h \
	sebsd.c \
	sebsd_syscall.c \
	sebsd_sysctl.c \
	avc.c \
	avc_audit.c \
	avtab.c \
	ebitmap.c \
	hashtab.c \
	init.c \
	policydb.c \
	services.c \
	sidtab.c \
	symtab.c \
	conditional.c \
	mls.c

.include <bsd.kmod.mk>
