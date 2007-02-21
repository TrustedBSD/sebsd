#
# Makefile for the security policy.
#
# Targets:
# 
# install - compile and install the policy configuration.
# load    - compile, install, and load the policy configuration.
# reload  - compile, install, and load/reload the policy configuration.
# relabel - relabel filesystems based on the file contexts configuration.
# policy  - compile the policy configuration locally for testing/development.
#
# The default target builds the policy and file_contexts, but doesn't install.
#

# Set to y if MLS is enabled in the module.
MLS= n
POLICYVERCOMPAT = 17

FLASKDIR = flask/
PREFIX = /usr
.if exists($(DESTDIR)/usr/bin/checkpolicy)
CHECKPOLICY = $(DESTDIR)/usr/bin/checkpolicy
.else
CHECKPOLICY = /usr/bin/checkpolicy
.endif
LOADPOLICY  = $(DESTDIR)/usr/sbin/load_policy
SETFILES = $(DESTDIR)/usr/sbin/setfiles
.if (POLICYVERCOMPAT)
POLICYVERTMP = $(POLICYVERCOMPAT)
POLICYVERCOMPATARGS = -c $(POLICYVERCOMPAT)
.else
POLICYVERTMP != ($(CHECKPOLICY) $(POLICYCOMPAT) -V |cut -f 1 -d ' ')
.endif
POLICYVER := policy.$(POLICYVERTMP)
POLICYBIN = policy.bin
INSTALLDIR = $(DESTDIR)/etc/security/sebsd
POLICYPATH = $(INSTALLDIR)/policy
SRCPATH = $(INSTALLDIR)/src
CONTEXTPATH = $(INSTALLDIR)/contexts
LOADPATH = $(POLICYPATH)/$(POLICYBIN)
FCPATH = $(CONTEXTPATH)/files/file_contexts

ALL_PROGRAM_MACROS := macros/program/*.te
ALL_MACROS := $(ALL_PROGRAM_MACROS) macros/*.te
ALL_TYPES := types/*.te
ALL_DOMAINS := domains/*.te domains/misc/*.te domains/program/*.te
ALLTEFILES := attrib.te tmp/program_used_flags.te $(ALL_MACROS) $(ALL_TYPES) $(ALL_DOMAINS) assert.te 
TE_RBAC_FILES := $(ALLTEFILES) rbac
ALL_TUNABLES := tunables/*.tun
ALL_TUNABLES =

POLICYFILES = $(FLASKDIR)/security_classes $(FLASKDIR)/initial_sids $(FLASKDIR)/access_vectors
.if $(MLS) == "y"
POLICYFILES += mls
.endif
POLICYFILES += $(ALL_TUNABLES) $(TE_RBAC_FILES)
POLICYFILES += users serviceusers
POLICYFILES += constraints initial_sid_contexts fs_use genfs_contexts net_contexts

M4 = $(REALDESTDIR)/usr/bin/m4 -Imacros -s
INSTALLCMD = install -c -o root -g wheel -m 400 
APPCONFDIR = $(DESTDIR)/etc/security

MULTILABELMOUNTS != ( /sbin/mount -t ufs -p | \
	/usr/bin/awk '{if (match($$4, "multilabel")) {print $$2}}')

UNUSED_TE_FILES := domains/program/unused/*.te

PROGRAMFILES := domains/program/*.te

FC = file_contexts/file_contexts
FCTEFILES := $(PROGRAMFILES:S/^domains\/program\//file_contexts\/program\//)
FCFILES = file_contexts/*.fc file_contexts/program/*.fc
FCFILES += $(FCTEFILES:.te=.fc)

APPDIR=$(CONTEXTPATH)
APPFILES = $(APPDIR)/default_contexts $(APPDIR)/default_type $(APPDIR)/initrc_context # $(APPDIR)/userhelper_context $(APPDIR)/failsafe_context
ROOTFILES = # $(APPDIR)/users/root

default: policy $(FC)

install: $(APPFILES) $(ROOTFILES) $(LOADPATH) $(FCPATH) 

$(APPDIR)/default_contexts: appconfig/default_contexts
	mkdir -p $(APPDIR)
	install -m 644 appconfig/default_contexts $@

$(APPDIR)/default_type: appconfig/default_type
	mkdir -p $(APPDIR)
	install -m 644 appconfig/default_type $@

$(APPDIR)/userhelper_context: appconfig/userhelper_context
	mkdir -p $(APPDIR)
	install -m 644 appconfig/userhelper_context $@

$(APPDIR)/initrc_context: appconfig/initrc_context
	mkdir -p $(APPDIR)
	install -m 644 appconfig/initrc_context $@

$(APPDIR)/failsafe_context: appconfig/failsafe_context
	mkdir -p $(APPDIR)
	install -m 644 appconfig/failsafe_context $@

$(APPDIR)/users/root: appconfig/root_default_contexts
	mkdir -p $(APPDIR)/users
	install -m 644 appconfig/root_default_contexts $@


$(LOADPATH):  $(POLICYPATH)/$(POLICYVER)
	ln -s $(POLICYVER) $(LOADPATH)

$(POLICYPATH)/$(POLICYVER): policy.conf $(CHECKPOLICY)
	mkdir -p $(POLICYPATH)
	$(CHECKPOLICY) $(POLICYVERCOMPATARGS) -o $@ policy.conf
# Note: Can't use install, so not sure how to deal with mode, user, and group
#	other than by default.

policy: $(POLICYBIN)

$(POLICYBIN): $(POLICYVER)
	ln -s $(POLICYVER) $@

$(POLICYVER):  policy.conf $(CHECKPOLICY)
	$(CHECKPOLICY) $(POLICYVERCOMPATARGS) -o $@ policy.conf

reload tmp/load: $(LOADPATH) $(FCPATH) 
	$(LOADPOLICY) $(POLICYPATH)/$(POLICYVER)
	touch tmp/load

load: tmp/load

enableaudit: policy.conf 
	grep -v dontaudit policy.conf > policy.audit
	mv policy.audit policy.conf

policy.conf: $(POLICYFILES) 
	mkdir -p tmp
	m4 $(M4PARAM) -Imacros -s $(POLICYFILES) > $@.tmp
	mv $@.tmp $@

install-src: /etc/security/sebsd
	rm -rf $(INSTALLDIR)/policy.old
	-mv $(INSTALLDIR)/policy $(INSTALLDIR)/policy.old
	cd ..; tar cf - policy | (cd $(INSTALLDIR); tar xf -)

tmp/program_used_flags.te: $(wildcard domains/program/*.te) domains/program
	mkdir -p tmp
	( cd domains/program/ ; for n in *.te ; do echo "define(\`$$n')"; done ) > $@.tmp
	( cd domains/misc/ ; for n in *.te ; do echo "define(\`$$n')"; done ) >> $@.tmp
	mv $@.tmp $@

FILESYSTEMS= $(MULTILABELMOUNTS)

checklabels: $(SETFILES)
	$(SETFILES) -v -n $(FC) $(FILESYSTEMS)

restorelabels: $(SETFILES)
	$(SETFILES) -v $(FC) $(FILESYSTEMS)

relabel:  $(FC) $(SETFILES)
	$(SETFILES) $(FC) $(FILESYSTEMS)

file_contexts/misc:
	mkdir -p file_contexts/misc

$(FCPATH): $(FC) 
	@mkdir -p $(CONTEXTPATH)/files
	install -m 644 $(FC) $(FCPATH)

$(FC): $(FCFILES) $(ALL_TUNABLES) domains/program domains/misc file_contexts/program file_contexts/misc users /etc/passwd
	@echo "Building file_contexts ..."
	@m4 $(ALL_TUNABLES) $(FCFILES) > $@.tmp
	@grep -v "^/root" $@.tmp > $@.root
	@sh ./genhomedircon $@.root  > $@
	@grep "^/root" $@.tmp >> $@
	@-rm $@.tmp $@.root

clean:
	rm -f $(POLICYBIN) $(POLICYVER)
	rm -f policy.conf
	rm -f tmp/*
	rm -f $(FC)

