#	$NetBSD: Makefile,v 1.1 2004/05/13 19:17:12 christos Exp $
# $FreeBSD: src/tools/regression/lib/libc/resolv/Makefile,v 1.4 2006/03/15 10:46:34 ru Exp $

PROG=		resolv
NO_MAN=

# Note: this test relies on being dynamically linked.  You will get a
# spurious PASS for a statically linked test.
DPADD+=		${LIBPTHREAD}
LDADD+=		-lpthread

regress: ${PROG}
	./${PROG} -r ${.CURDIR}/mach

.include <bsd.prog.mk>
