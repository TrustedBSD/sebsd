# $FreeBSD: src/release/doc/de_DE.ISO8859-1/errata/Makefile,v 1.1 2002/03/12 18:35:39 ue Exp $
# $FreeBSDde: de-docproj/relnotes/de_DE.ISO8859-1/errata/Makefile,v 1.4 2002/03/10 18:26:34 ue Exp $
# $Id$
# basiert auf: 1.5

RELN_ROOT?= ${.CURDIR}/../..
.ifdef NO_LANGCODE_IN_DESTDIR
DESTDIR?= ${DOCDIR}/errata
.else
DESTDIR?= ${DOCDIR}/de_DE.ISO8859-1/errata
.endif

DOC?= article
FORMATS?= html
INSTALL_COMPRESSED?= gz
INSTALL_ONLY_COMPRESSED?=

# SGML content
SRCS+=	article.sgml

.include "${RELN_ROOT}/share/mk/doc.relnotes.mk"
.include "${DOC_PREFIX}/share/mk/doc.project.mk"
