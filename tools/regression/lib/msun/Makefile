# $FreeBSD: src/tools/regression/lib/msun/Makefile,v 1.5 2005/03/25 06:24:46 das Exp $

TESTS=	test-fenv test-ilogb test-lrint test-lround test-next test-rem
CFLAGS+= -O0 -lm
ARCH!=	uname -m
.if ${ARCH} == "alpha"
CFLAGS+= -mieee-with-inexact -mfp-rounding-mode=d
.endif

.PHONY: tests
tests: ${TESTS}
	for p in ${TESTS}; do ${.OBJDIR}/$$p; done

.PHONY: clean
clean:
	-rm -f ${TESTS}
