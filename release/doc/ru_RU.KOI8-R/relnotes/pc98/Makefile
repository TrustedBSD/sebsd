# The FreeBSD Russian Documentation Project
#
# $FreeBSD: src/release/doc/ru_RU.KOI8-R/relnotes/pc98/Makefile,v 1.1 2004/05/21 11:59:55 den Exp $
# $FreeBSDru: frdp/release/doc/ru_RU.KOI8-R/relnotes/pc98/Makefile,v 1.1 2004/05/20 07:02:26 den Exp $
#
# Original revision: 1.1

RELN_ROOT?= ${.CURDIR}/../../..

DOC?= article
FORMATS?= html
INSTALL_COMPRESSED?= gz
INSTALL_ONLY_COMPRESSED?=

JADEFLAGS+=	-V %generate-article-toc%

# SGML content
SRCS+=	article.sgml
SRCS+=	../common/relnotes.ent
SRCS+=	../common/new.sgml

.include "${RELN_ROOT}/share/mk/doc.relnotes.mk"
.include "${DOC_PREFIX}/share/mk/doc.project.mk"
