# $FreeBSD: src/release/doc/en_US.ISO8859-1/hardware/ia64/Makefile,v 1.3 2004/08/03 22:12:45 simon Exp $

RELN_ROOT?= ${.CURDIR}/../../..

DOC?= article
FORMATS?= html
INSTALL_COMPRESSED?= gz
INSTALL_ONLY_COMPRESSED?=

JADEFLAGS+=	-V %generate-article-toc%

# SGML content
SRCS+=	article.sgml 
# SRCS+=	proc-ia64.sgml 
SRCS+=	../common/hw.ent
SRCS+=	../common/artheader.sgml
SRCS+=	../common/dev.sgml
SRCS+=	${DEV-AUTODIR}/catalog-auto
SRCS+=	${DEV-AUTODIR}/dev-auto.sgml

.include "${RELN_ROOT}/share/mk/doc.relnotes.mk"
.include "${DOC_PREFIX}/share/mk/doc.project.mk"
