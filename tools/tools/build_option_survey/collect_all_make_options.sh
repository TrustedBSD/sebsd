#!/bin/sh
#
# This file is in the public domain
#
# $FreeBSD: src/tools/tools/build_option_survey/collect_all_make_options.sh,v 1.1 2005/08/09 09:27:11 phk Exp $

find ../../.. -name 'Makefile*' -print | 
    xargs grep 'defined' | 
	sed '
	/release\/Makefile/d
	/tools\/tools/d
	s/^[^:]*://
	/^[ 	]*#/d
	s/\|\|/\
	/g
	s/\&\&/\
	/g
	' | sed '
	/defined[ 	]*(/!d
	s/).*//
	s/.*(//
	/{/d
	/[$]/d
	' | sort -u |
	sed '
	# build directives
	/^NO_CLEAN$/d
	/^NO_CLEANDIR$/d
	/^NO_KERNELCLEAN$/d
	/^NO_KERNELCONFIG$/d
	/^NO_KERNELDEPEND$/d
	/^NO_PORTSUPDATE$/d
	/^NO_DOCUPDATE$/d
	/^LDSCRIPT$/d
	/^DEBUG$/d
	/^SMP$/d
	# Do not even think about it :-)
	/^NOTYET$/d
	/^notdef*$/d
	# Unknown magic
	/^_.*$/d
	/^MODULES_WITH_WORLD$/d
	/^BATCH_DELETE_OLD_FILES$/d
	/^SUBDIR_OVERRIDE$/d
	' > _.options
