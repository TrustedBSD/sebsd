/*	$FreeBSD: src/contrib/ipfilter/lib/optprintv6.c,v 1.3 2005/12/30 11:52:24 guido Exp $	*/

/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */
#include "ipf.h"


#ifdef	USE_INET6

void optprintv6(sec, optmsk, optbits)
u_short *sec;
u_long optmsk, optbits;
{
	u_short secmsk = sec[0], secbits = sec[1];
	struct ipopt_names *io;
	char *s;

	s = " v6hdrs ";
	for (io = v6ionames; io->on_name; io++)
		if ((io->on_bit & optmsk) &&
		    ((io->on_bit & optmsk) == (io->on_bit & optbits))) {
			printf("%s%s", s, io->on_name);
			s = ",";
		}

	if ((optmsk && (optmsk != optbits)) ||
	    (secmsk && (secmsk != secbits))) {
		s = " ";
		printf(" not v6hdrs");
		if (optmsk != optbits) {
			for (io = v6ionames; io->on_name; io++)
				if ((io->on_bit & optmsk) &&
				    ((io->on_bit & optmsk) !=
				     (io->on_bit & optbits))) {
					printf("%s%s", s, io->on_name);
					s = ",";
				}
		}

	}
}
#endif
