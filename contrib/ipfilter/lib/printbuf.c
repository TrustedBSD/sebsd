/*	$FreeBSD: src/contrib/ipfilter/lib/printbuf.c,v 1.3 2005/12/30 11:52:24 guido Exp $	*/

/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include <ctype.h>

#include "ipf.h"


void printbuf(buf, len, zend)
char *buf;
int len, zend;
{
	char *s, c;
	int i;

	for (s = buf, i = len; i; i--) {
		c = *s++;
		if (ISPRINT(c))
			putchar(c);
		else
			printf("\\%03o", c);
		if ((c == '\0') && zend)
			break;
	}
}
