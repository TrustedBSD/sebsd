/*
 * $FreeBSD: src/lib/libpthread/thread/thr_vfork.c,v 1.4 2006/03/13 00:59:51 deischen Exp $
 */
#include <unistd.h>

#include "thr_private.h"

LT10_COMPAT_PRIVATE(_vfork);
LT10_COMPAT_DEFAULT(vfork);

__weak_reference(_vfork, vfork);

int
_vfork(void)
{
	return (fork());
}
