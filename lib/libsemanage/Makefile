#
# $FreeBSD: $
#

.PATH: ${.CURDIR} ${.CURDIR}/../../contrib/sebsd/libsemanage/src
.PATH: ${.CURDIR}/../../contrib/sebsd/libsemanage/include
.PATH: ${.CURDIR}/../../contrib/sebsd/libsemanage/man/man3

MAINTAINER= cboss@nai.com
LIB= semanage
CFLAGS+= -I${.CURDIR}/../../contrib/sebsd/libsemanage/include
CFLAGS+= -I${.CURDIR}/../../contrib/sebsd/libsemanage/src
YFLAGS= -d -p semanage_

SRCS=	boolean_record.c booleans_active.c booleans_activedb.c \
	booleans_file.c booleans_local.c booleans_policy.c \
	booleans_policydb.c context_record.c database.c database_activedb.c \
	database_file.c database_join.c database_llist.c \
	database_policydb.c debug.c direct_api.c fcontext_record.c \
	fcontexts_file.c fcontexts_local.c fcontexts_policy.c \
	handle.c iface_record.c interfaces_file.c interfaces_local.c \
	interfaces_policy.c interfaces_policydb.c modules.c \
	node_record.c nodes_file.c nodes_local.c nodes_policy.c \
	nodes_policydb.c parse_utils.c policy_components.c port_record.c \
	ports_file.c ports_local.c ports_policy.c ports_policydb.c \
	semanage_store.c seuser_record.c \
	seusers_file.c seusers_local.c seusers_policy.c user_base_record.c \
	user_extra_record.c user_record.c users_base_file.c \
	users_base_policydb.c users_extra_file.c users_join.c \
	users_local.c users_policy.c
SRCS+=	conf-parse.y conf-scan.l
SRCS+=	strverscmp.c

INCSDIR=${INCLUDEDIR}/semanage

INCS=	semanage/boolean_record.h semanage/booleans_active.h \
	semanage/booleans_local.h semanage/booleans_policy.h \
	semanage/context_record.h semanage/debug.h \
	semanage/fcontext_record.h semanage/fcontexts_local.h \
	semanage/fcontexts_policy.h semanage/handle.h \
	semanage/iface_record.h semanage/interfaces_local.h \
	semanage/interfaces_policy.h semanage/modules.h \
	semanage/node_record.h semanage/nodes_local.h \
	semanage/nodes_policy.h semanage/port_record.h \
	semanage/ports_local.h semanage/ports_policy.h semanage/semanage.h \
	semanage/seuser_record.h semanage/seusers_local.h \
	semanage/seusers_policy.h semanage/user_record.h \
	semanage/users_local.h semanage/users_policy.h

MAN=	semanage_bool_set_active.3 semanage_user_count_local.3 \
	semanage_user_del_local.3 semanage_user_exists_local.3 \
	semanage_user_iterate_local.3 semanage_user_list_local.3 \
	semanage_user_modify_local.3 semanage_user_query_local.3

MLINKS+= semanage_user_count_local.3 semanage_bool_count.3
MLINKS+= semanage_user_count_local.3 semanage_bool_count_active.3
MLINKS+= semanage_user_count_local.3 semanage_bool_count_local.3
MLINKS+= semanage_user_del_local.3 semanage_bool_del_local.3
MLINKS+= semanage_user_exists_local.3 semanage_bool_exists.3
MLINKS+= semanage_user_exists_local.3 semanage_bool_exists_active.3
MLINKS+= semanage_user_exists_local.3 semanage_bool_exists_local.3
MLINKS+= semanage_user_iterate_local.3 semanage_bool_iterate.3
MLINKS+= semanage_user_iterate_local.3 semanage_bool_iterate_active.3
MLINKS+= semanage_user_iterate_local.3 semanage_bool_iterate_local.3
MLINKS+= semanage_user_list_local.3 semanage_bool_list.3
MLINKS+= semanage_user_list_local.3 semanage_bool_list_active.3
MLINKS+= semanage_user_list_local.3 semanage_bool_list_local.3
MLINKS+= semanage_user_modify_local.3 semanage_bool_modify_local.3
MLINKS+= semanage_user_query_local.3 semanage_bool_query.3
MLINKS+= semanage_user_query_local.3 semanage_bool_query_active.3
MLINKS+= semanage_user_query_local.3 semanage_bool_query_local.3
MLINKS+= semanage_user_count_local.3 semanage_fcontext_count.3
MLINKS+= semanage_user_count_local.3 semanage_fcontext_count_local.3
MLINKS+= semanage_user_del_local.3 semanage_fcontext_del_local.3
MLINKS+= semanage_user_exists_local.3 semanage_fcontext_exists.3
MLINKS+= semanage_user_exists_local.3 semanage_fcontext_exists_local.3
MLINKS+= semanage_user_iterate_local.3 semanage_fcontext_iterate.3
MLINKS+= semanage_user_iterate_local.3 semanage_fcontext_iterate_local.3
MLINKS+= semanage_user_list_local.3 semanage_fcontext_list.3
MLINKS+= semanage_user_list_local.3 semanage_fcontext_list_local.3
MLINKS+= semanage_user_modify_local.3 semanage_fcontext_modify_local.3
MLINKS+= semanage_user_query_local.3 semanage_fcontext_query.3
MLINKS+= semanage_user_query_local.3 semanage_fcontext_query_local.3
MLINKS+= semanage_user_count_local.3 semanage_iface_count.3
MLINKS+= semanage_user_count_local.3 semanage_iface_count_local.3
MLINKS+= semanage_user_del_local.3 semanage_iface_del_local.3
MLINKS+= semanage_user_exists_local.3 semanage_iface_exists.3
MLINKS+= semanage_user_exists_local.3 semanage_iface_exists_local.3
MLINKS+= semanage_user_iterate_local.3 semanage_iface_iterate.3
MLINKS+= semanage_user_iterate_local.3 semanage_iface_iterate_local.3
MLINKS+= semanage_user_list_local.3 semanage_iface_list.3
MLINKS+= semanage_user_list_local.3 semanage_iface_list_local.3
MLINKS+= semanage_user_modify_local.3 semanage_iface_modify_local.3
MLINKS+= semanage_user_query_local.3 semanage_iface_query.3
MLINKS+= semanage_user_query_local.3 semanage_iface_query_local.3
MLINKS+= semanage_user_count_local.3 semanage_node_count.3
MLINKS+= semanage_user_count_local.3 semanage_node_count_local.3
MLINKS+= semanage_user_del_local.3 semanage_node_del_local.3
MLINKS+= semanage_user_exists_local.3 semanage_node_exists.3
MLINKS+= semanage_user_exists_local.3 semanage_node_exists_local.3
MLINKS+= semanage_user_iterate_local.3 semanage_node_iterate.3
MLINKS+= semanage_user_iterate_local.3 semanage_node_iterate_local.3
MLINKS+= semanage_user_list_local.3 semanage_node_list.3
MLINKS+= semanage_user_list_local.3 semanage_node_list_local.3
MLINKS+= semanage_user_modify_local.3 semanage_node_modify_local.3
MLINKS+= semanage_user_query_local.3 semanage_node_query.3
MLINKS+= semanage_user_query_local.3 semanage_node_query_local.3
MLINKS+= semanage_user_count_local.3 semanage_port_count.3
MLINKS+= semanage_user_count_local.3 semanage_port_count_local.3
MLINKS+= semanage_user_del_local.3 semanage_port_del_local.3
MLINKS+= semanage_user_exists_local.3 semanage_port_exists.3
MLINKS+= semanage_user_exists_local.3 semanage_port_exists_local.3
MLINKS+= semanage_user_iterate_local.3 semanage_port_iterate.3
MLINKS+= semanage_user_iterate_local.3 semanage_port_iterate_local.3
MLINKS+= semanage_user_list_local.3 semanage_port_list.3
MLINKS+= semanage_user_list_local.3 semanage_port_list_local.3
MLINKS+= semanage_user_modify_local.3 semanage_port_modify_local.3
MLINKS+= semanage_user_query_local.3 semanage_port_query.3
MLINKS+= semanage_user_query_local.3 semanage_port_query_local.3
MLINKS+= semanage_user_count_local.3 semanage_seuser_count.3
MLINKS+= semanage_user_count_local.3 semanage_seuser_count_local.3
MLINKS+= semanage_user_del_local.3 semanage_seuser_del_local.3
MLINKS+= semanage_user_exists_local.3 semanage_seuser_exists.3
MLINKS+= semanage_user_exists_local.3 semanage_seuser_exists_local.3
MLINKS+= semanage_user_iterate_local.3 semanage_seuser_iterate.3
MLINKS+= semanage_user_iterate_local.3 semanage_seuser_iterate_local.3
MLINKS+= semanage_user_list_local.3 semanage_seuser_list.3
MLINKS+= semanage_user_list_local.3 semanage_seuser_list_local.3
MLINKS+= semanage_user_modify_local.3 semanage_seuser_modify_local.3
MLINKS+= semanage_user_query_local.3 semanage_seuser_query.3
MLINKS+= semanage_user_query_local.3 semanage_seuser_query_local.3
MLINKS+= semanage_user_count_local.3 semanage_user_count.3
MLINKS+= semanage_user_exists_local.3 semanage_user_exists.3
MLINKS+= semanage_user_iterate_local.3 semanage_user_iterate.3
MLINKS+= semanage_user_list_local.3 semanage_user_list.3
MLINKS+= semanage_user_query_local.3 semanage_user_query.3

.include <bsd.lib.mk>
