# Common defines for all of /sys/boot/pc98/
#
# $FreeBSD: src/sys/boot/pc98/Makefile.inc,v 1.6 2005/09/13 08:27:38 nyan Exp $

BINDIR?=	/boot

LOADER_ADDRESS?=0x100000
CFLAGS+=	-ffreestanding -mpreferred-stack-boundary=2 \
		-mno-mmx -mno-3dnow -mno-sse -mno-sse2 -mno-sse3
LDFLAGS+=	-nostdlib

# BTX components
.if exists(${.OBJDIR}/../btx)
BTXDIR=		${.OBJDIR}/../btx
.else
BTXDIR=		${.CURDIR}/../btx
.endif
BTXLDR=		${BTXDIR}/btxldr/btxldr
BTXKERN=	${BTXDIR}/btx/btx
BTXCRT=		${BTXDIR}/lib/crt0.o
