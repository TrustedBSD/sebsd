# $FreeBSD: src/release/doc/de_DE.ISO8859-1/hardware/i386/Makefile,v 1.1 2002/03/12 18:35:41 ue Exp $
# $FreeBSDde: de-docproj/relnotes/de_DE.ISO8859-1/hardware/i386/Makefile,v 1.2 2002/03/10 18:41:36 ue Exp $
# $Id$
# basiert auf: 1.5

RELN_ROOT?= ${.CURDIR}/../../..

DOC?= article
FORMATS?= html
INSTALL_COMPRESSED?= gz
INSTALL_ONLY_COMPRESSED?=

JADEFLAGS+=    -V %generate-article-toc%

# SGML content
SRCS+=	article.sgml 
SRCS+=	proc-i386.sgml 
SRCS+=	../common/hw.ent
SRCS+=	../common/artheader.sgml
SRCS+=	../common/dev.sgml

.include "${RELN_ROOT}/share/mk/doc.relnotes.mk"
.include "${DOC_PREFIX}/share/mk/doc.project.mk"
