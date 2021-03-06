#!/bin/sh
# $FreeBSD: src/tools/regression/usr.bin/pkill/pkill-LF.t,v 1.1 2005/08/25 20:13:58 pjd Exp $

base=`basename $0`

echo "1..2"

name="pkill -LF <pidfile>"
pidfile=`mktemp /tmp/$base.XXXXXX` || exit 1
sleep=`mktemp /tmp/$base.XXXXXX` || exit 1
ln -sf /bin/sleep $sleep
daemon -p $pidfile $sleep 5
sleep 0.3
pkill -f -L -F $pidfile $sleep
ec=$?
case $ec in
0)
	echo "ok 1 - $name"
	;;
*)
	echo "not ok 1 - $name"
	;;
esac

# Be sure we cannot kill process which pidfile is not locked.
$sleep 5 &
sleep 0.3
chpid=$!
echo $chpid > $pidfile
pkill -f -L -F $pidfile $sleep 2>/dev/null
ec=$?
case $ec in
0)
	echo "not ok 2 - $name"
	;;
*)
	echo "ok 2 - $name"
	;;
esac

kill "$chpid"
rm -f $pidfile
rm -f $sleep
