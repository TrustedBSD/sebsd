# $FreeBSD: src/tools/tools/tinderbox/etc/Makefile,v 1.10 2005/07/20 20:01:37 des Exp $

ETCFILES	 =
ETCFILES	+= default.rc
ETCFILES	+= releng_4.rc update_releng_4.rc
ETCFILES	+= releng_5.rc update_releng_5.rc
ETCFILES	+= releng_6.rc update_releng_6.rc
ETCFILES	+= head.rc update_head.rc
ETCDIR		?= ${HOME}/etc
ETCOWN		?= ${USER}
ETCGRP		?= ${USER}

realinstall:
.for FILE in ${ETCFILES}
	${INSTALL} -m0644 -o${ETCOWN} -g${ETCGRP} ${.CURDIR}/${FILE} ${ETCDIR}
.endfor

.include <bsd.prog.mk>
