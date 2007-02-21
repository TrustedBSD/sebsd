#ifndef lint
static const char rcsid[] =
    "@(#) $Id$ (LBL)";
#endif

#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

int
usleep(register u_int useconds)
{
#ifdef HAVE_NANOSLEEP
	struct timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	return (nanosleep(&ts, NULL));
#else
	struct timeval tv;

	tv.tv_sec = useconds / 1000000;
	tv.tv_usec = useconds % 1000000;
	return (select(0, NULL, NULL, NULL, &tv));
#endif
}
