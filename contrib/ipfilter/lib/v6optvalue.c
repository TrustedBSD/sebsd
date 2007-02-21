/*	$FreeBSD: src/contrib/ipfilter/lib/v6optvalue.c,v 1.3 2005/12/30 11:52:24 guido Exp $	*/

/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */
#include "ipf.h"



u_32_t getv6optbyname(optname)
char *optname;
{
#ifdef	USE_INET6
	struct ipopt_names *io;

	for (io = v6ionames; io->on_name; io++)
		if (!strcasecmp(optname, io->on_name))
			return io->on_bit;
#endif
	return -1;
}


u_32_t getv6optbyvalue(optval)
int optval;
{
#ifdef	USE_INET6
	struct ipopt_names *io;

	for (io = v6ionames; io->on_name; io++)
		if (io->on_value == optval)
			return io->on_bit;
#endif
	return -1;
}
