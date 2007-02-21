#
# $FreeBSD: $
#

.PATH: ${.CURDIR} ${.CURDIR}/../../contrib/sebsd/libselinux/src
.PATH: ${.CURDIR}/../../contrib/sebsd/libselinux/include
.PATH: ${.CURDIR}/../../contrib/sebsd/libselinux/man/man3
.PATH: ${.CURDIR}/../../sys/security/sebsd
.PATH: ${.CURDIR}/../../contrib/sebsd/policy/flask

MAINTAINER= cboss@nai.com
LIB= selinux
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../../contrib/sebsd/libselinux/include -I${.CURDIR}/../../contrib/sebsd/libsepol/include 
CFLAGS+=-I${.CURDIR}/../../sys
#LDADD+=	-L${.OBJDIR}/../libpam/libpam ${MINUSLPAM}
#DPADD+=	${LIBPAM}

SRCS=	avc.c avc_internal.c avc_sidtab.c booleans.c canonicalize_context.c \
	checkAccess.c check_context.c compute_av.c compute_create.c \
	compute_member.c compute_relabel.c compute_user.c context.c \
	disable.c enabled.c fgetfilecon.c freecon.c freeconary.c \
	fsetfilecon.c get_context_list.c get_default_type.c \
	getcon.c getenforce.c getexeccon.c \
	getfilecon.c getpeercon.c getpidcon.c getprevcon.c init.c \
	is_customizable_type.c lgetfilecon.c load_policy.c \
	lsetfilecon.c matchmediacon.c matchpathcon.c policyvers.c \
	query_user_context.c sebsd_config.c \
	selinux_check_securetty_context.c setcon.c setenforce.c \
	setfilecon.c setrans_client.c seusers.c

# The following require kernel support for fs and exec contexts
#SRCS += getfscreatecon.c setfscreatecon.c setexeccon.c

# The following are Linux-specific
#SRCS += procattr.c rpm.c

INCSDIR=${INCLUDEDIR}/selinux

INCS=	selinux/av_permissions.h selinux/avc.h selinux/context.h \
		selinux/flask.h selinux/get_context_list.h \
		selinux/get_default_type.h selinux/selinux.h sebsd_syscalls.h

MAN=	avc_add_callback.3 avc_cache_stats.3 avc_context_to_sid.3 \
	avc_has_perm.3 avc_init.3 context_new.3 freecon.3 \
	get_ordered_context_list.3 getcon.3 getexeccon.3 getfilecon.3 \
	getseuserbyname.3 is_context_customizable.3 \
	is_selinux_enabled.3 matchmediacon.3 matchpathcon.3 \
	security_check_context.3 security_compute_av.3 \
	security_getenforce.3 security_load_booleans.3 \
	security_load_policy.3 security_policyvers.3 \
	selinux_binary_policy_path.3 selinux_getenforcemode.3 \
	selinux_policy_root.3 setfilecon.3

MLINKS=	avc_has_perm.3 avc_audit.3 \
	avc_cache_stats.3 avc_av_stats.3 \
	avc_init.3 avc_cleanup.3 \
	avc_init.3 avc_destroy.3 \
	avc_has_perm.3 avc_entry_ref_init.3 \
	avc_has_perm.3 avc_has_perm_noaudit.3 \
	avc_init.3 avc_reset.3 \
	avc_cache_stats.3 avc_sid_stats.3 \
	avc_context_to_sid.3 avc_sid_to_context.3 \
	security_compute_av.3 checkPasswdAccess.3 \
	context_new.3 context_free.3 \
	context_new.3 context_range_get.3 \
	context_new.3 context_range_set.3 \
	context_new.3 context_role_get.3 \
	context_new.3 context_role_set.3 \
	context_new.3 context_type_get.3 \
	context_new.3 context_type_set.3 \
	context_new.3 context_user_get.3 \
	context_new.3 context_user_set.3 \
	freecon.3 freeconary.3 \
	setfilecon.3 fsetfilecon.3 \
	get_ordered_context_list.3 get_default_context.3 \
	get_ordered_context_list.3 get_default_context_with_level.3 \
	get_ordered_context_list.3 get_default_context_with_role.3 \
	get_ordered_context_list.3 get_default_context_with_rolelevel.3 \
	get_ordered_context_list.3 get_ordered_context_list_with_level.3 \
	getcon.3 getpeercon.3 \
	getcon.3 getpidcon.3 \
	getcon.3 getprevcon.3 \
	setfilecon.3 lsetfilecon.3 \
	get_ordered_context_list.3 manual_user_enter_context.3 \
	get_ordered_context_list.3 query_user_context.3 \
	getexeccon.3 rpm_execcon.3 \
	security_load_booleans.3 security_commit_booleans.3 \
	security_compute_av.3 security_compute_create.3 \
	security_compute_av.3 security_compute_relabel.3 \
	security_compute_av.3 security_compute_user.3 \
	security_load_booleans.3 security_get_boolean_active.3 \
	security_load_booleans.3 security_get_boolean_names.3 \
	security_load_booleans.3 security_get_boolean_pending.3 \
	security_load_booleans.3 security_set_boolean.3 \
	security_getenforce.3 security_setenforce.3 \
	selinux_binary_policy_path.3 selinux_booleans_path.3 \
	selinux_binary_policy_path.3 selinux_contexts_path.3 \
	selinux_binary_policy_path.3 selinux_default_context_path.3 \
	selinux_binary_policy_path.3 selinux_failsafe_context_path.3 \
	selinux_binary_policy_path.3 selinux_file_context_path.3 \
	selinux_binary_policy_path.3 selinux_media_context_path.3 \
	selinux_binary_policy_path.3 selinux_removable_context_path.3 \
	selinux_binary_policy_path.3 selinux_user_contexts_path.3 \
	matchpathcon.3 set_matchpathcon_printf.3 \
	getcon.3 setcon.3 \
	getexeccon.3 setexeccon.3 \
	avc_context_to_sid.3 sidget.3 \
	avc_context_to_sid.3 sidput.3

# Not currently supported
#MAN+=	getfscreatecon.3
#MLINKS+=getfscreatecon.3 setfscreatecon.3

.include <bsd.lib.mk>
