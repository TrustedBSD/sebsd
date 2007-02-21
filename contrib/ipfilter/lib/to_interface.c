/*	$FreeBSD: src/contrib/ipfilter/lib/to_interface.c,v 1.3 2005/12/30 11:52:24 guido Exp $	*/

/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


int to_interface(fdp, to, linenum)
frdest_t *fdp;
char *to;
int linenum;
{
	char *s;

	s = strchr(to, ':');
	fdp->fd_ifp = NULL;
	if (s) {
		*s++ = '\0';
		if (hostnum((u_32_t *)&fdp->fd_ip, s, linenum, NULL) == -1)
			return -1;
	}
	(void) strncpy(fdp->fd_ifname, to, sizeof(fdp->fd_ifname) - 1);
	fdp->fd_ifname[sizeof(fdp->fd_ifname) - 1] = '\0';
	return 0;
}
