/*	$FreeBSD: src/contrib/ipfilter/lib/printlog.c,v 1.3 2005/12/30 11:52:24 guido Exp $	*/

/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

#include <syslog.h>


void printlog(fp)
frentry_t *fp;
{
	char *s, *u;

	printf("log");
	if (fp->fr_flags & FR_LOGBODY)
		printf(" body");
	if (fp->fr_flags & FR_LOGFIRST)
		printf(" first");
	if (fp->fr_flags & FR_LOGORBLOCK)
		printf(" or-block");
	if (fp->fr_loglevel != 0xffff) {
		printf(" level ");
		s = fac_toname(fp->fr_loglevel);
		if (s == NULL)
			s = "!!!";
		u = pri_toname(fp->fr_loglevel);
		if (u == NULL)
			u = "!!!";
		if (*s)
			printf("%s.%s", s, u);
		else
			printf("%s", u);
	}
}
