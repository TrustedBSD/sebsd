# $FreeBSD$
# Install SEBSD example policy files.

NOMAN = noman
NOOBJ = noobj

SRCDIR = ${.CURDIR}/../../../contrib/sebsd/policy
DSTDIR = ${DESTDIR}/${BINDIR}/sebsd/policy

all:
	echo ${DSTDIR}

install:
	cd ${SRCDIR}; cpio -p -R${BINOWN}:${BINGRP} ${DSTDIR} < files.lst


.include <bsd.prog.mk>
