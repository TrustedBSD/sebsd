# $FreeBSD: src/usr.sbin/ntp/libntp/Makefile,v 1.10 2004/10/24 15:33:04 ru Exp $

.PATH: ${.CURDIR}/../../../contrib/ntp/libntp \
	${.CURDIR}/../../../contrib/ntp/libisc

LIB= ntp
INTERNALLIB=

NTP_SRCS=	a_md5encrypt.c	adjtime.c	atoint.c	atolfp.c \
	atouint.c	audio.c		authkeys.c \
	authreadkeys.c	authusekey.c	binio.c \
	buftvtots.c	caljulian.c	calleapwhen.c	caltontp.c \
	calyearstart.c	clocktime.c	clocktypes.c	decodenetnum.c \
	dofptoa.c	dolfptoa.c	emalloc.c	findconfig.c \
	fptoa.c		fptoms.c	getopt.c	gpstolfp.c \
	hextoint.c	hextolfp.c	humandate.c	icom.c \
	ieee754io.c	inttoa.c	iosignal.c	lib_strbuf.c \
	machines.c	md5c.c		memmove.c	mfp_mul.c \
	mfptoa.c	mfptoms.c	modetoa.c	mstolfp.c \
	msutotsf.c	msyslog.c	netof.c		ntp_rfc2553.c \
	numtoa.c	numtohost.c	octtoint.c	prettydate.c \
	ranny.c	recvbuff.c	refnumtoa.c	socktoa.c \
	socktohost.c	strstr.c	systime_s.c	statestr.c \
	syssignal.c	systime.c	tsftomsu.c	tstotv.c \
	tvtoa.c	tvtots.c	uglydate.c	uinttoa.c \
	utvtoa.c	ymd2yd.c 

ISC_SRCS= assertions.c error.c inet_ntop.c interfaceiter.c \
	isc_strerror.c lib.c mem.c msgcat.c net.c

SRCS=	${NTP_SRCS} ${ISC_SRCS}

CFLAGS+= -I${.CURDIR}/../../../contrib/ntp/include -I${.CURDIR}/../

.include <bsd.lib.mk>
