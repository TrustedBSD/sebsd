# $FreeBSD: src/lib/libc/alpha/Makefile.inc,v 1.9 2006/03/16 14:22:19 ru Exp $
#
# Machine dependent definitions for the alpha architecture.
#

# On Alpha, long double is just double precision.
MDSRCS+=machdep_ldisd.c
SYM_MAPS+=${.CURDIR}/alpha/Symbol.map
