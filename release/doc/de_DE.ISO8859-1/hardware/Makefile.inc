# $FreeBSD: src/release/doc/de_DE.ISO8859-1/hardware/Makefile.inc,v 1.1 2002/03/12 18:35:39 ue Exp $
# $FreeBSDde: de-docproj/relnotes/de_DE.ISO8859-1/hardware/Makefile.inc,v 1.2 2002/03/10 18:41:33 ue Exp $
# $Id$
# basiert auf: 1.2

.ifdef NO_LANGCODE_IN_DESTDIR
DESTDIR?=       ${DOCDIR}/hardware/${.CURDIR:T}
.else
DESTDIR?=       ${DOCDIR}/de_DE.ISO8859-1/hardware/${.CURDIR:T}
.endif

