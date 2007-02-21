/*	$FreeBSD: src/contrib/ipfilter/lib/loglevel.c,v 1.3 2005/12/30 11:52:24 guido Exp $	*/

/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


int loglevel(cpp, facpri, linenum)
char **cpp;
u_int *facpri;
int linenum;
{
	int fac, pri;
	char *s;

	fac = 0;
	pri = 0;
	if (!*++cpp) {
		fprintf(stderr, "%d: %s\n", linenum,
			"missing identifier after level");
		return -1;
	}

	s = strchr(*cpp, '.');
	if (s) {
		*s++ = '\0';
		fac = fac_findname(*cpp);
		if (fac == -1) {
			fprintf(stderr, "%d: %s %s\n", linenum,
				"Unknown facility", *cpp);
			return -1;
		}
		pri = pri_findname(s);
		if (pri == -1) {
			fprintf(stderr, "%d: %s %s\n", linenum,
				"Unknown priority", s);
			return -1;
		}
	} else {
		pri = pri_findname(*cpp);
		if (pri == -1) {
			fprintf(stderr, "%d: %s %s\n", linenum,
				"Unknown priority", *cpp);
			return -1;
		}
	}
	*facpri = fac|pri;
	return 0;
}
