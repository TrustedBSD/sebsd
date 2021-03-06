# $FreeBSD: src/lib/libpthread/Makefile,v 1.56 2006/03/16 15:17:47 deischen Exp $
#
# All library objects contain FreeBSD revision strings by default; they may be
# excluded as a space-saving measure.  To produce a library that does
# not contain these strings, add -DSTRIP_FBSDID (see <sys/cdefs.h>) to CFLAGS
# below.  Note, there are no IDs for syscall stubs whose sources are generated.
# To included legacy CSRG sccsid strings, add -DLIBC_SCCS and -DSYSLIBC_SCCS
# (for system call stubs) to CFLAGS below.  -DSYSLIBC_SCCS affects just the
# system call stubs.
.if ${MACHINE_ARCH} == "alpha" || ${MACHINE_ARCH} == "sparc64"
LIB=kse
.else
LIB=pthread
.endif
SHLIB_MAJOR= 2
CFLAGS+=-DPTHREAD_KERNEL
CFLAGS+=-I${.CURDIR}/../libc/include -I${.CURDIR}/thread \
	-I${.CURDIR}/../../include
CFLAGS+=-I${.CURDIR}/arch/${MACHINE_ARCH}/include
CFLAGS+=-I${.CURDIR}/sys
CFLAGS+=-I${.CURDIR}/../../libexec/rtld-elf
CFLAGS+=-I${.CURDIR}/../../libexec/rtld-elf/${MACHINE_ARCH}
CFLAGS+=-fno-builtin

# Uncomment this if you want libpthread to contain debug information for
# thread locking.
CFLAGS+=-D_LOCK_DEBUG
#CFLAGS+= -g

# Uncomment this if you want to build a 1:1 threading mode library
# however it is no longer strictly conformed to POSIX
# CFLAGS+=-DSYSTEM_SCOPE_ONLY

# Enable extra internal consistancy checks.
CFLAGS+=-D_PTHREADS_INVARIANTS -Wall

VERSION_MAP=${.CURDIR}/pthread.map

.if defined(SYMVER_ENABLED)
# Remove this if library version is bumped and LIBPTHREAD_1_0
# compatability hacks are removed (see thread/thr_private.h).
LDFLAGS+=-Wl,-zmuldefs
CFLAGS+=-DSYMBOL_VERSIONING
.endif

PRECIOUSLIB=

.include "${.CURDIR}/arch/${MACHINE_ARCH}/Makefile.inc"
.include "${.CURDIR}/support/Makefile.inc"
.include "${.CURDIR}/sys/Makefile.inc"
.include "${.CURDIR}/thread/Makefile.inc"

.include <bsd.lib.mk>
