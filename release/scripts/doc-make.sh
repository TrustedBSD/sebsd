#!/bin/sh
#
# $FreeBSD: src/release/scripts/doc-make.sh,v 1.3 2002/04/23 22:16:40 obrien Exp $
#

# Create the doc dist.
if [ -d ${RD}/trees/base/usr/share/doc ]; then
	( cd ${RD}/trees/base/usr/share/doc;
	find . | cpio -dumpl ${RD}/trees/doc/usr/share/doc ) &&
	rm -rf ${RD}/trees/base/usr/share/doc
fi
