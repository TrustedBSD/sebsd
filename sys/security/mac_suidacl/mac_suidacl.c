/*-
 * Copyright (c) 2005 Samy Al Bahra.
 * Copyright (c) 2003-2004 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/vnode.h>
#include <sys/mac.h>
#include <sys/imgact.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/sysctl.h>
#include <sys/jail.h>
#include <sys/mac_policy.h>

SYSCTL_DECL(_security_mac);

SYSCTL_NODE(_security_mac, OID_AUTO, suidacl, CTLFLAG_RW, 0,
	"TrustedBSD mac_suidacl policy controls");
	
static int mac_suidacl_enabled = 0;
SYSCTL_INT(_security_mac_suidacl, OID_AUTO, enabled, CTLFLAG_RW,
	&mac_suidacl_enabled, 0, "Enforce suidacl policy");
TUNABLE_INT("security.mac.suidacl.enabled", &mac_suidacl_enabled);

MALLOC_DEFINE(M_SUIDACL, "suidacl rule", "Rules for mac_suidacl");

#define	RULE_ANY	0
#define	RULE_UID	1
#define	RULE_GID	2
#define	RULE_IGNORE	0
#define	RULE_SYSTEM	-1

#define	RULE_TYPE_ALL		0
#define	RULE_TYPE_EXECVE	1
#define	RULE_TYPE_SETXID	2
#define	RULE_TYPE_SETUID	3
#define	RULE_TYPE_SETEUID	4
#define	RULE_TYPE_SETREUID	5
#define	RULE_TYPE_SETRESUID	6
#define	RULE_TYPE_SETGID	7
#define	RULE_TYPE_SETEGID	8
#define	RULE_TYPE_SETREGID	9
#define	RULE_TYPE_SETRESGID	10
#define	RULE_TYPE_SETGROUPS	11

#define	GID_STRING		"gid"
#define	UID_STRING		"uid"
#define	ALL_STRING		"all"
#define	IGNORE_STRING		"all"
#define SYSTEM_STRING		"none"
#define EXECVE_STRING		"execve"
#define	SETXID_STRING		"setxid"
#define	SETUID_STRING		"setuid"
#define	SETEUID_STRING		"seteuid"
#define	SETGID_STRING		"setgid"
#define	SETEGID_STRING		"setegid"
#define	SETREUID_STRING		"setreuid"
#define	SETREGID_STRING		"setregid"
#define	SETRESUID_STRING	"setresuid"
#define	SETRESGID_STRING	"setresgid"
#define	SETGROUPS_STRING	"setgroups"

#define MAC_RULE_STRING_LEN	1024

/* all:uid:5:setuid, all:uid:5:setuid:uid:5 */
struct rule {
	int			r_pr_id;
	id_t			r_id;
	int			r_idtype;
	int			r_type;

	TAILQ_ENTRY(rule)	r_entries;
};

static struct mtx			rule_mtx;
static TAILQ_HEAD(rulehead, rule)	rule_head;
static char				rule_string[MAC_RULE_STRING_LEN];

static void
toast_rules(struct rulehead *head)
{
	struct rule *rule;

	while ((rule = TAILQ_FIRST(head)) != NULL) {
		TAILQ_REMOVE(head, rule, r_entries);
		free(rule, M_SUIDACL);
	}
}

/*
 * Note: due to races, there is not a single serializable order
 * between parallel calls to the sysctl.
 */
static void
destroy(struct mac_policy_conf *mpc)
{

	mtx_destroy(&rule_mtx);
	toast_rules(&rule_head);
}

static void
init(struct mac_policy_conf *mpc)
{

	mtx_init(&rule_mtx, "rule_mtx", NULL, MTX_DEF);
	TAILQ_INIT(&rule_head);
}

/*
 * Note: parsing routines are destructive on the passed string.
 */
static int
parse_rule_element(char *element, struct rule **rule)
{
	char *idtype, *id, *rtype, *prison, *p;
	struct rule *new;
	int error;

	error = 0;
	new = malloc(sizeof(*new), M_SUIDACL, M_ZERO | M_WAITOK);

	idtype = NULL;
	prison = strsep(&element, ":");
	if (prison == NULL) {
		error = EINVAL;
		goto out;
	}

	if (strcmp(prison, IGNORE_STRING) == 0)
		new->r_pr_id = RULE_IGNORE;
	else if (strcmp(prison, SYSTEM_STRING) == 0)
		new->r_pr_id = RULE_SYSTEM;
	else if (strcmp(prison, UID_STRING) &&
		 strcmp(prison, GID_STRING)) {
		new->r_pr_id = strtol(prison, &p, 10);
		if (*p != '\0' || new->r_pr_id < 0) {
			error = EINVAL;
			goto out;
		}
	} else
		idtype = prison;

	new->r_pr_id = RULE_IGNORE;

	if (idtype == NULL) {
		idtype = strsep(&element, ":");

		if (idtype == NULL) {
			error = EINVAL;
			goto out;
		}
	}

	id = strsep(&element, ":");
	if (id == NULL) {
		error = EINVAL;
		goto out;
	}
	new->r_id = strtol(id, &p, 10);
	if (*p != '\0') {
		error = EINVAL;
		goto out;
	}

	if (strcmp(idtype, UID_STRING) == 0)
		new->r_idtype = RULE_UID;
	else if (strcmp(idtype, GID_STRING) == 0)
		new->r_idtype = RULE_GID;
	else {
		error = EINVAL;
		goto out;
	}

	rtype = element;
	if (rtype == NULL) {
		error = EINVAL;
		goto out;
	}

	if (strcmp(rtype, ALL_STRING) == 0)
		new->r_type = RULE_TYPE_ALL;
	else if (strcmp(rtype, EXECVE_STRING) == 0)
		new->r_type = RULE_TYPE_EXECVE;
	else if (strcmp(rtype, SETXID_STRING) == 0)
		new->r_type = RULE_TYPE_SETXID;
	else if (strcmp(rtype, SETUID_STRING) == 0)
		new->r_type = RULE_TYPE_SETUID;
	else if (strcmp(rtype, SETEUID_STRING) == 0)
		new->r_type = RULE_TYPE_SETEUID;
	else if (strcmp(rtype, SETGID_STRING) == 0)
		new->r_type = RULE_TYPE_SETGID;
	else if (strcmp(rtype, SETEGID_STRING) == 0)
		new->r_type = RULE_TYPE_SETEGID;
	else if (strcmp(rtype, SETREUID_STRING) == 0)
		new->r_type = RULE_TYPE_SETREUID;
	else if (strcmp(rtype, SETREGID_STRING) == 0)
		new->r_type = RULE_TYPE_SETREGID;
	else if (strcmp(rtype, SETRESUID_STRING) == 0)
		new->r_type = RULE_TYPE_SETRESUID;
	else if (strcmp(rtype, SETRESGID_STRING) == 0)
		new->r_type = RULE_TYPE_SETRESGID;
	else if (strcmp(rtype, SETGROUPS_STRING) == 0)
		new->r_type = RULE_TYPE_SETGROUPS;
	else {
		error = EINVAL;
		goto out;
	}

out:
	if (error != 0) {
		free(new, M_SUIDACL);
		*rule = NULL;
	} else
		*rule = new;
	return (error);
}

static int
parse_rules(char *string, struct rulehead *head)
{
	struct rule *new;
	char *element;
	int error;

	error = 0;
	while ((element = strsep(&string, ",")) != NULL) {
		if (strlen(element) == 0)
			continue;
		error = parse_rule_element(element, &new);
		if (error)
			goto out;
		TAILQ_INSERT_TAIL(head, new, r_entries);
	}
out:
	if (error != 0)
		toast_rules(head);
	return (error);
}

static int
sysctl_rules(SYSCTL_HANDLER_ARGS)
{
	char *string, *copy_string, *new_string;
	struct rulehead head, save_head;
	struct rule *rule;
	int error;

	new_string = NULL;
	if (req->newptr == NULL) {
		new_string = malloc(MAC_RULE_STRING_LEN, M_SUIDACL,
		    M_WAITOK | M_ZERO);
		strcpy(new_string, rule_string);
		string = new_string;
	} else
		string = rule_string;

	error = sysctl_handle_string(oidp, string, MAC_RULE_STRING_LEN, req);
	if (error)
		goto out;

	if (req->newptr != NULL) {
		copy_string = strdup(string, M_SUIDACL);
		TAILQ_INIT(&head);
		error = parse_rules(copy_string, &head);
		free(copy_string, M_SUIDACL);
		if (error)
			goto out;

		TAILQ_INIT(&save_head);
		mtx_lock(&rule_mtx);
		/*
		 * XXX: Unfortunately, TAILQ doesn't yet have a supported
		 * assignment operator to copy one queue to another, due
	 	 * to a self-referential pointer in the tailq header.
		 * For now, do it the old-fashioned way.
		 */
		while ((rule = TAILQ_FIRST(&rule_head)) != NULL) {
			TAILQ_REMOVE(&rule_head, rule, r_entries);
			TAILQ_INSERT_HEAD(&save_head, rule, r_entries);
		}
		while ((rule = TAILQ_FIRST(&head)) != NULL) {
			TAILQ_REMOVE(&head, rule, r_entries);
			TAILQ_INSERT_HEAD(&rule_head, rule, r_entries);
		}
		strcpy(rule_string, string);
		mtx_unlock(&rule_mtx);
		toast_rules(&save_head);
	}
out:
	if (new_string != NULL)
		free(new_string, M_SUIDACL);
	return (error);
}

SYSCTL_PROC(_security_mac_suidacl, OID_AUTO, rules,
	CTLTYPE_STRING|CTLFLAG_RW, 0, 0, sysctl_rules, "A", "Rules");

/*
 * The logic of all rule-checking is contained in this function
 */
static int
check_general(struct ucred *cred, int ruletype)
{
	int error = 0;
	struct rule *current;

	/*
	 * XXXRW: Should we be using CAP_SETGID and CAP_SETUID here?
	 */
	if ((mac_suidacl_enabled == 0) || !suser_cred(cred, 0))
		return (0);

	mtx_lock(&rule_mtx);
	for (current = TAILQ_FIRST(&rule_head);
		 current != NULL;
		 current = TAILQ_NEXT(current, r_entries)) {
			if (current->r_type == RULE_TYPE_ALL ||
			    (ruletype == RULE_TYPE_EXECVE ? 
				0 : current->r_type == RULE_TYPE_SETXID) ||
			    current->r_type == ruletype) {
				if (current->r_pr_id == RULE_SYSTEM && cred->cr_prison)
					continue;
				else if (current->r_pr_id) {
					if (!cred->cr_prison ||
					    (cred->cr_prison->pr_id != current->r_pr_id))
						continue;
				}

				if (current->r_idtype == RULE_UID &&
				    cred->cr_ruid != current->r_id)
					continue;
	
				if (current->r_idtype == RULE_GID &&
				    cred->cr_rgid != current->r_id)
					continue;

				error = EPERM;
				break;
			}
	}

	mtx_unlock(&rule_mtx);
	return (error);
}

static int
check_vnode_exec(struct ucred *cred, struct vnode *vp, struct label *label,
		 struct image_params *imgp, struct label *execlabel)
{
	struct vattr *vap;

	vap = imgp->attr;
	if (!(vap->va_mode & VSUID || vap->va_mode & VSGID))
		return (0);

	return (check_general(cred, RULE_TYPE_EXECVE));
}

static int
check_proc_setuid(struct ucred *cred, uid_t uid)
{

	return (check_general(cred, RULE_TYPE_SETUID));
}

static int
check_proc_seteuid(struct ucred *cred, uid_t euid)
{

	return (check_general(cred, RULE_TYPE_SETEUID));
}

static int
check_proc_setgid(struct ucred *cred, gid_t gid)
{

	return (check_general(cred, RULE_TYPE_SETGID));
}

static int
check_proc_setegid(struct ucred *cred, gid_t egid)
{

	return (check_general(cred, RULE_TYPE_SETEGID));
}

static int
check_proc_setgroups(struct ucred *cred, int ngroups,
	gid_t *gidset)
{

	return (check_general(cred, RULE_TYPE_SETGROUPS));
}

static int
check_proc_setreuid(struct ucred *cred, uid_t ruid,
	uid_t euid)
{

	return (check_general(cred, RULE_TYPE_SETREUID));
}

static int
check_proc_setregid(struct ucred *cred, gid_t rgid,
	gid_t egid)
{

	return (check_general(cred, RULE_TYPE_SETREGID));
}

static int
check_proc_setresuid(struct ucred *cred, uid_t ruid,
	gid_t euid, gid_t suid)
{

	return (check_general(cred, RULE_TYPE_SETRESUID));
}

static int
check_proc_setresgid(struct ucred *cred, gid_t rgid,
	gid_t egid, gid_t sgid)
{

	return (check_general(cred, RULE_TYPE_SETRESGID));
}	

static struct mac_policy_ops mac_suidacl_ops =
{
	.mpo_destroy = destroy,
	.mpo_init = init,
	.mpo_check_vnode_exec = check_vnode_exec,
	.mpo_check_proc_setuid = check_proc_setuid,
	.mpo_check_proc_seteuid = check_proc_seteuid,
	.mpo_check_proc_setgid = check_proc_setgid,
	.mpo_check_proc_setegid = check_proc_setegid,
	.mpo_check_proc_setgroups = check_proc_setgroups,
	.mpo_check_proc_setreuid = check_proc_setreuid,
	.mpo_check_proc_setregid = check_proc_setregid,
	.mpo_check_proc_setresuid = check_proc_setresuid,
	.mpo_check_proc_setresgid = check_proc_setresgid
};

MAC_POLICY_SET(&mac_suidacl_ops, trustedbsd_mac_suidacl,
	"TrustedBSD MAC/suidacl", MPC_LOADTIME_FLAG_UNLOADOK, NULL);
