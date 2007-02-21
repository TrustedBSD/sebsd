# $FreeBSD: src/gnu/lib/Makefile,v 1.41 2006/03/17 18:54:22 ru Exp $

.include <bsd.own.mk>

SUBDIR= csu libgcc libgcov libdialog libregex libreadline

# libsupc++ uses libstdc++ headers, although 'make includes' should
# have taken care of that already.
.if ${MK_CXX} != "no"
SUBDIR+= libstdc++ libsupc++
.endif

.if ${MK_OBJC} != "no"
SUBDIR+= libobjc
.endif

.if ${MK_FORTRAN} != "no"
SUBDIR+= libg2c
.endif

.include <bsd.subdir.mk>
