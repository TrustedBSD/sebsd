/*	$FreeBSD: src/contrib/ipfilter/lib/getproto.c,v 1.3 2005/12/30 11:52:23 guido Exp $	*/

#include "ipf.h"

int getproto(name)
char *name;
{
	struct protoent *p;
	char *s;

	for (s = name; *s != '\0'; s++)
		if (!ISDIGIT(*s))
			break;
	if (*s == '\0')
		return atoi(name);

#ifdef _AIX51
	/*
	 * For some bogus reason, "ip" is 252 in /etc/protocols on AIX 5
	 */
	if (!strcasecmp(name, "ip"))
		return 0;
#endif

	p = getprotobyname(name);
	if (p != NULL)
		return p->p_proto;
	return -1;
}
