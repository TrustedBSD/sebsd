#!/bin/sh
#

sysctl security.mac.chkexec >/dev/null
if [ $? -ne 0 ]; then
	echo ERROR: mac_chkexec must be loaded for these tests >/dev/stderr
	exit 1
fi

sysctl security.mac.chkexec.ignore_untagged=0
sysctl security.mac.chkexec.enforce=0
rm -fr /tmp/prog.sh

echo "1..11"

#
# Make sure that we are dis-allowing the execution of programs which do
# not have a checksum associated with them. This prevents people from
# uploading non-trusted binaries to the system and running them.
#
echo "#!/bin/sh" > /tmp/prog.sh
chmod +x /tmp/prog.sh
sysctl security.mac.chkexec.enforce=1
/tmp/prog.sh
if [ $? -ne 0 ]; then
	echo ok 1
else
	echo not ok 1
fi

#
# Make sure that security.mac.chkexec.ignore_untagged works as designed,
# even though this opens a huge security hole in the policy
#
sysctl security.mac.chkexec.ignore_untagged=1
/tmp/prog.sh
if [ $? -eq 0 ]; then
	echo ok 2
else
	echo not ok 2
fi

#
# Make sure execution works ?
#
sysctl security.mac.chkexec.ignore_untagged=0
sysctl security.mac.chkexec.enforce=0
/tmp/prog.sh
if [ $? -eq 0 ]; then
	echo ok 3
else
	echo not ok 3
fi

#
# Make sure if we change the program what we are NOT allowed to execute
# this. This might represent somebody back dooring a script or program,
# or making an un-planned change to the a program. Either way, we do NOT
# want to execute this program anymore.
#
sysctl security.mac.chkexec.enforce=1
echo "echo test" >> /tmp/prog.sh
/tmp/prog.sh
if [ $? -eq 0 ]; then
	echo not ok 4 
else
	echo ok 4 
fi

#
# We should not be allowed to set dependencies when the policy is
# being enforced, so setfhash should fail.
#
rm /tmp/file.conf
touch /tmp/file.conf
setfhash -m /tmp/file.conf /tmp/prog.sh
if [ $? -eq 0 ]; then
	echo not ok 5
else
	echo ok 5
fi

#
# Stop enforcing the policy and set the dependency, this should work,
# if it doesn't then there are probably other issues which need to be
# looked at.
#
sysctl security.mac.chkexec.enforce=0
setfhash -m /tmp/file.conf /tmp/prog.sh
if [ $? -eq 0 ]; then
	echo ok 6
else
	echo not ok 6
fi

#
# We have set the dependency, but we have not triggered the calculation
# and storage of the dependency yet. Thus when we execute the program
# it should fail because the checksum can not be verified for the
# dependency.
#
sysctl security.mac.chkexec.enforce=1
/tmp/prog.sh
if [ $? -eq 0 ]; then
	echo not ok 7
else
	echo ok 7
fi

#
# Stop enforcing the policy, calculate/store the checksum for the dependency
# and execute the program. This should all work properly.
#
sysctl security.mac.chkexec.enforce=0
setfhash /tmp/file.conf
sysctl security.mac.chkexec.enforce=1
/tmp/prog.sh
if [ $? -eq 0 ]; then
	echo ok 8
else
	echo not ok 8
fi

#
# Modify the dependency, this should result in the program failing to execute.
#
echo 0 > /tmp/file.conf
/tmp/prog.sh
if [ $? -eq 0 ]; then
	echo not ok 9
else
	echo ok 9
fi

#
# Attempt to trigger the calculation and storage of an object's hash while the
# policy is being enforced. This should fail.
#
setfhash /tmp/prog.sh
if [ $? -eq 0 ]; then
	echo not ok 10
else
	echo ok 10
fi

#
# Attempt to set the EA using setextattr, this should fail when the policy
# is loaded.
# 
setextattr system chkexec test /tmp/prog.sh
if [ $? -eq 0 ]; then
	echo not ok 11
else
	echo ok 11
fi
