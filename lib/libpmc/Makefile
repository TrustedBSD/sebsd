# $FreeBSD: src/lib/libpmc/Makefile,v 1.4 2005/06/09 19:45:06 jkoshy Exp $

LIB=	pmc

SRCS=	libpmc.c pmclog.c
INCS=	pmc.h pmclog.h

WARNS?=	6

MAN=	pmc.3 pmclog.3

MLINKS+= \
	pmc.3 pmc_allocate.3 \
	pmc.3 pmc_attach.3 \
	pmc.3 pmc_capabilities.3 \
	pmc.3 pmc_configure_logfile.3 \
	pmc.3 pmc_cpuinfo.3 \
	pmc.3 pmc_detach.3 \
	pmc.3 pmc_disable.3 \
	pmc.3 pmc_enable.3 \
	pmc.3 pmc_event_names_of_class.3 \
	pmc.3 pmc_flush_logfile.3 \
	pmc.3 pmc_get_driver_stats.3 \
	pmc.3 pmc_init.3 \
	pmc.3 pmc_name_of_capability.3 \
	pmc.3 pmc_name_of_class.3 \
	pmc.3 pmc_name_of_cputype.3 \
	pmc.3 pmc_name_of_event.3 \
	pmc.3 pmc_name_of_mode.3 \
	pmc.3 pmc_name_of_state.3 \
	pmc.3 pmc_ncpu.3 \
	pmc.3 pmc_npmc.3 \
	pmc.3 pmc_pmcinfo.3 \
	pmc.3 pmc_read.3 \
	pmc.3 pmc_release.3 \
	pmc.3 pmc_rw.3 \
	pmc.3 pmc_set.3 \
	pmc.3 pmc_start.3 \
	pmc.3 pmc_stop.3 \
	pmc.3 pmc_width.3 \
	pmc.3 pmc_write.3 \
	pmc.3 pmc_writelog.3 \
	pmc.3 pmc_x86_get_msr.3

MLINKS+= \
	pmclog.3 pmclog_open.3 \
	pmclog.3 pmclog_close.3 \
	pmclog.3 pmclog_feed.3 \
	pmclog.3 pmclog_read.3

.include <bsd.lib.mk>
