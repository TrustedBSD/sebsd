#!/bin/sh
#
# $FreeBSD: src/release/scripts/games-install.sh,v 1.3 2001/04/08 23:09:21 obrien Exp $
#

if [ "`id -u`" != "0" ]; then
	echo "Sorry, this must be done as root."
	exit 1
fi
cat games.?? | tar --unlink -xpzf - -C ${DESTDIR:-/}
exit 0
