#	@(#)Makefile.inc	8.1 (Berkeley) 6/4/93
# $FreeBSD: src/lib/libc/i386/gen/Makefile.inc,v 1.22 2004/08/15 16:18:03 dfr Exp $

SRCS+=	_ctx_start.S _setjmp.S _set_tp.c alloca.S fabs.S \
	flt_rounds.c infinity.c ldexp.c makecontext.c modf.S \
	rfork_thread.S setjmp.S signalcontext.c sigsetjmp.S
