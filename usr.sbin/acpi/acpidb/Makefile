# $FreeBSD: src/usr.sbin/acpi/acpidb/Makefile,v 1.7 2005/11/01 22:44:08 jkim Exp $

PROG=	acpidb
SRCS=	acpidb.c
SRCS+=	osunixxf.c

# debugger
SRCS+=	dbcmds.c dbdisply.c dbexec.c dbfileio.c dbhistry.c	\
	dbinput.c dbstats.c dbutils.c dbxface.c

# disassembler
SRCS+=	dmbuffer.c dmnames.c dmobject.c dmopcode.c dmresrc.c	\
	dmresrcl.c dmresrcs.c dmutils.c dmwalk.c

# events
SRCS+=	evevent.c evgpe.c evgpeblk.c evmisc.c evregion.c	\
	evrgnini.c evsci.c evxface.c evxfevnt.c evxfregn.c

# hardware
SRCS+=	hwacpi.c hwgpe.c hwregs.c hwsleep.c

# interpreter/dispatcher
SRCS+=	dsfield.c dsinit.c dsmethod.c dsmthdat.c dsobject.c	\
	dsopcode.c dsutils.c dswexec.c dswload.c dswscope.c	\
	dswstate.c

# interpreter/executer
SRCS+=	exconfig.c exconvrt.c excreate.c exdump.c exfield.c	\
	exfldio.c exmisc.c exmutex.c exnames.c exoparg1.c	\
	exoparg2.c exoparg3.c exoparg6.c exprep.c exregion.c	\
	exresnte.c exresolv.c exresop.c exstore.c exstoren.c	\
	exstorob.c exsystem.c exutils.c

# interpreter/parser
SRCS+=	psargs.c psloop.c psopcode.c psparse.c psscope.c	\
	pstree.c psutils.c pswalk.c psxface.c

# namespace
SRCS+=	nsaccess.c nsalloc.c nsdump.c nseval.c nsinit.c		\
	nsload.c nsnames.c nsobject.c nsparse.c nssearch.c	\
	nsutils.c nswalk.c nsxfeval.c nsxfname.c nsxfobj.c

# resources
SRCS+=	rsaddr.c rscalc.c rscreate.c rsdump.c rsinfo.c		\
	rsio.c rsirq.c rslist.c rsmemory.c rsmisc.c		\
	rsutils.c rsxface.c

# tables
SRCS+=	tbconvrt.c tbget.c tbgetall.c tbinstal.c tbrsdt.c	\
	tbutils.c tbxface.c tbxfroot.c

# tools/acpiexec
SRCS+=	aeexec.c

# utilities
SRCS+=	utalloc.c utcache.c utcopy.c utdebug.c utdelete.c	\
	uteval.c utglobal.c utinit.c utmath.c utmisc.c		\
	utmutex.c utobject.c utstate.c utxface.c

MAN=	acpidb.8
WARNS?=	2

CFLAGS+= -DACPI_APPLICATION -DACPI_DEBUG_OUTPUT -DACPI_DEBUGGER \
	-DACPI_DISASSEMBLER

.include <bsd.prog.mk>
