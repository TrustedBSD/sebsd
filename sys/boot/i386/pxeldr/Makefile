# $FreeBSD: src/sys/boot/i386/pxeldr/Makefile,v 1.16 2004/04/27 19:45:16 ru Exp $

# Pick up ../Makefile.inc early.
.include <bsd.init.mk>

PROG=	${LDR}
INTERNALPROG=
FILES=	${BOOT}
MAN=	${BOOT}.8
SRCS=	${LDR}.S
CLEANFILES= ${BOOT}

BOOT=	pxeboot
LDR=	pxeldr
ORG=	0x7c00
LOADER=	loader

.if defined(BOOT_PXELDR_PROBE_KEYBOARD)
CFLAGS+=-DPROBE_KEYBOARD
.endif

.if defined(BOOT_PXELDR_ALWAYS_SERIAL)
CFLAGS+=-DALWAYS_SERIAL
.endif

LOADERBIN= ${.OBJDIR}/../loader/loader.bin

CLEANFILES+= ${BOOT}.tmp

${BOOT}: ${LDR} ${LOADER}
	cat ${LDR} ${LOADER} > ${.TARGET}.tmp
	dd if=${.TARGET}.tmp of=${.TARGET} obs=2k conv=osync
	rm ${.TARGET}.tmp

LDFLAGS+= -N -e start -Ttext ${ORG} -Wl,-S,--oformat,binary

CLEANFILES+= ${LOADER}

${LOADER}: ${LOADERBIN} ${BTXLDR} ${BTXKERN}
	btxld -v -f aout -e ${LOADER_ADDRESS} -o ${.TARGET} -l ${BTXLDR} \
	    -b ${BTXKERN} ${LOADERBIN}

.include <bsd.prog.mk>
