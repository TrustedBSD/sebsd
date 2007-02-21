%define type strict
Summary: SELinux %{type} policy configuration
Name: selinux-policy-%{type}
Version: 1.16
Release: 1
License: GPL
Group: System Environment/Base
Source: http://www.nsa.gov/selinux/archives/policy-%{version}.tgz
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-buildroot

BuildArch: noarch
BuildRequires: checkpolicy >= 1.10 m4 policycoreutils >= 1.6-7
Obsoletes: policy

%description
Security-enhanced Linux is a patch of the Linux® kernel and a number
of utilities with enhanced security functionality designed to add
mandatory access controls to Linux.  The Security-enhanced Linux
kernel contains new architectural components originally developed to
improve the security of the Flask operating system. These
architectural components provide general support for the enforcement
of many kinds of mandatory access control policies, including those
based on the concepts of Type Enforcement®, Role-based Access
Control, and Multi-level Security.

This package contains the SELinux example policy configuration along
with the Flask configuration information and the application
configuration files.  

%prep
%setup -q -n policy-%{version}

%build
mv domains/misc/unused/*.te domains/misc
mv domains/program/unused/*.te domains/program/
(cd domains/program/; mv uwimapd.te dpk* gatekeeper* qmail* xprint* uml_net* tiny* seuser* unused/)
make policy
rm -rf tmp

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}/root
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/selinux/%{type}/contexts/users
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/selinux/%{type}/contexts/files
make DESTDIR="${RPM_BUILD_ROOT}" install
make clean
make DESTDIR="${RPM_BUILD_ROOT}" install-src
rm -rf "${RPM_BUILD_ROOT}%{_sysconfdir}/selinux/%{type}/src/policy/targeted"

%clean
rm -rf ${RPM_BUILD_ROOT}

%files 
%defattr(-,root,root)
%dir %{_sysconfdir}/selinux/%{type}
%config(noreplace) %{_sysconfdir}/selinux/%{type}/policy/policy\.*
%config(noreplace) %{_sysconfdir}/selinux/%{type}/contexts/files/file_contexts
%config(noreplace) %{_sysconfdir}/selinux/%{type}/contexts/default_contexts
%config(noreplace) %{_sysconfdir}/selinux/%{type}/contexts/default_type
%config(noreplace) %{_sysconfdir}/selinux/%{type}/contexts/initrc_context
%config(noreplace) %{_sysconfdir}/selinux/%{type}/contexts/failsafe_context
%config(noreplace) %{_sysconfdir}/selinux/%{type}/contexts/userhelper_context
%config(noreplace) %{_sysconfdir}/selinux/%{type}/contexts/users/root

%post
if [ ! -f /etc/selinux/config ]; then
	if [ -f /etc/sysconfig/selinux ]; then 
		cp /etc/sysconfig/selinux /etc/selinux/config
		echo "
# SELINUXTYPE= can take one of these two values:
#	targeted - Only targeted network daemons are protected.
#	strict - Full SELinux protection.
SELINUXTYPE=strict " >> /etc/selinux/config
		rm -f /etc/sysconfig/selinux
	else
		echo "
# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#	enforcing - SELinux security policy is enforced.
#	permissive - SELinux prints warnings instead of enforcing.
#	disabled - No SELinux policy is loaded.
SELINUX=enforcing
# SELINUXTYPE= can take one of these two values:
#	targeted - Only targeted network daemons are protected.
#	strict - Full SELinux protection.
SELINUXTYPE=targeted " > /etc/selinux/config

	fi
fi
ln -sf /etc/selinux/config /etc/sysconfig/selinux 
restorecon /etc/selinux/config

if [ -x /usr/bin/selinuxenabled ] && /usr/bin/selinuxenabled && [ -e /selinux/policyvers ]; then

	SELINUXTYPE=targeted
	if [ -f /etc/selinux/config ]; then
		. /etc/selinux/config
	else
		if [ -f /etc/selinux/config ]; then
			SELINUXTYPE=strict
			. /etc/sysconfig/selinux
		fi
	fi
	if [ "${SELINUXTYPE}" = "%{type}" ]; then 
		/usr/sbin/load_policy /etc/selinux/%{type}/policy/policy.`cat /selinux/policyvers`
	fi
fi
exit 0

%package sources
Summary: SELinux example policy configuration source files 
Group: System Environment/Base
Requires: m4 make checkpolicy >= 1.10 policycoreutils >= 1.6-7 
Requires: selinux-policy-%{type} = %{version}-%{release}
BuildRequires: checkpolicy  policycoreutils >= 1.6-7 
Obsoletes: policy-sources

%description sources
This subpackage includes the source files used to build the policy
configuration.  Includes policy.conf and the Makefiles, macros and
source files for it.

%files sources
%defattr(0600,root,root,0700)
%config(noreplace) %{_sysconfdir}/selinux/%{type}/src/policy/users
%config(noreplace) %{_sysconfdir}/selinux/%{type}/src/policy/tunables/*
%dir %{_sysconfdir}/selinux/%{type}/src
%dir %{_sysconfdir}/selinux/%{type}/src/policy
%config %{_sysconfdir}/selinux/%{type}/src/policy/policy\.*
%config %{_sysconfdir}/selinux/%{type}/src/policy/appconfig
%config %{_sysconfdir}/selinux/%{type}/src/policy/assert.te
%config %{_sysconfdir}/selinux/%{type}/src/policy/attrib.te
%{_sysconfdir}/selinux/%{type}/src/policy/ChangeLog
%config %{_sysconfdir}/selinux/%{type}/src/policy/constraints
%{_sysconfdir}/selinux/%{type}/src/policy/COPYING
%config %{_sysconfdir}/selinux/%{type}/src/policy/domains
%config %{_sysconfdir}/selinux/%{type}/src/policy/file_contexts/types.fc
%config %{_sysconfdir}/selinux/%{type}/src/policy/file_contexts/program
%config %{_sysconfdir}/selinux/%{type}/src/policy/file_contexts/misc
%config %{_sysconfdir}/selinux/%{type}/src/policy/flask
%config %{_sysconfdir}/selinux/%{type}/src/policy/fs_use
%config %{_sysconfdir}/selinux/%{type}/src/policy/genfs_contexts
%config %{_sysconfdir}/selinux/%{type}/src/policy/initial_sid_contexts
%config %{_sysconfdir}/selinux/%{type}/src/policy/macros
%{_sysconfdir}/selinux/%{type}/src/policy/Makefile
%config %{_sysconfdir}/selinux/%{type}/src/policy/mls
%config %{_sysconfdir}/selinux/%{type}/src/policy/net_contexts
%config %{_sysconfdir}/selinux/%{type}/src/policy/rbac
%{_sysconfdir}/selinux/%{type}/src/policy/README
%config %{_sysconfdir}/selinux/%{type}/src/policy/serviceusers
%config %{_sysconfdir}/selinux/%{type}/src/policy/types
%{_sysconfdir}/selinux/%{type}/src/policy/VERSION

%post sources
if [ -x /usr/bin/selinuxenabled ]; then 
   make -W /etc/selinux/%{type}/src/policy/users \
        -C /etc/selinux/%{type}/src/policy > /dev/null 2>&1
   SELINUXTYPE=targeted
   if [ -f /etc/selinux/config ]; then
	. /etc/selinux/config
   else
	if [ -f /etc/selinux/config ]; then
		SELINUXTYPE=strict
		. /etc/sysconfig/selinux
	fi
   fi
   if [ "${SELINUXTYPE}" = "%{type}" ]; then 
	 /usr/bin/selinuxenabled && [ -e /selinux/policyvers ] && \
		make -C /etc/selinux/%{type}/src/policy load 
   fi
fi
exit 0

%changelog
* Mon Jun 14 2004 Dan Walsh <dwalsh@redhat.com> 1.13.4-6
- Remove uwimapd patch

* Wed Jun 9 2004 Dan Walsh <dwalsh@redhat.com> 1.13.4-5
- Fix patch

* Wed Jun 9 2004 Dan Walsh <dwalsh@redhat.com> 1.13.4-4
- Add Additional Russell fixes

* Tue Jun 8 2004 Dan Walsh <dwalsh@redhat.com> 1.13.4-3
- Add Hotplug fixes

* Mon Jun 7 2004 Dan Walsh <dwalsh@redhat.com> 1.13.4-2
- Add most of Russell's mods

* Mon Jun 7 2004 Dan Walsh <dwalsh@redhat.com> 1.13.4-1
- Handle newrole changes for new design
- Update to latest from NSA

* Thu Jun 3 2004 Dan Walsh <dwalsh@redhat.com> 1.13.3-3
- Handle updating /etc/selinux/config

* Wed Jun 2 2004 Dan Walsh <dwalsh@redhat.com> 1.13.3-1
- Update to latest from NSA
- Fix numerous bugs

* Wed Jun 2 2004 Dan Walsh <dwalsh@redhat.com> 1.13.2-7
- Fix su policy for terminal rename with new pam_selinux.

* Wed Jun 2 2004 Dan Walsh <dwalsh@redhat.com> 1.13.2-6
- Fix policy for setfiles and restorecon

* Wed Jun 2 2004 Dan Walsh <dwalsh@redhat.com> 1.13.2-5
- Add tunables subdir

* Tue Jun 1 2004 Dan Walsh <dwalsh@redhat.com> 1.13.2-4
- Fix hotplug and udev 

* Tue Jun 1 2004 Dan Walsh <dwalsh@redhat.com> 1.13.2-3
- Fix handling of selinux_config_t and default_context_t

* Fri May 28 2004 Dan Walsh <dwalsh@redhat.com> 1.13.2-2
- Only update policy if this policy is running

* Fri May 28 2004 Dan Walsh <dwalsh@redhat.com> 1.13.2-1
- Update to match NSA

* Thu May 27 2004 Dan Walsh <dwalsh@redhat.com> 1.13.1-2
- Change location of file_contexts and add new security contexts

* Mon May 24 2004 Dan Walsh <dwalsh@redhat.com> 1.13.1-1
- Initial version created from policy.spec

