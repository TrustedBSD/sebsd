#include <sys/types.h>
#include <sys/sysctl.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dso.h"

/* Indices for file paths arrays. */
#define BASEDIR			0
#define POLICYDIR		1
#define BINPOLICY		2
#define CONTEXTS_DIR		3
#define FILE_CONTEXTS		4
#define HOMEDIR_CONTEXTS	5
#define DEFAULT_CONTEXTS	6
#define USER_CONTEXTS		7
#define FAILSAFE_CONTEXT	8
#define DEFAULT_TYPE		9
#define BOOLEANS		10
#define MEDIA_CONTEXTS		11
#define REMOVABLE_CONTEXT	12
#define CUSTOMIZABLE_TYPES	13
#define USERS_DIR		14
#define SEUSERS			15
#define TRANSLATIONS		16
#define NETFILTER_CONTEXTS	17
#define FILE_CONTEXTS_HOMEDIR	18
#define FILE_CONTEXTS_LOCAL	19
#define SECURETTY_TYPES		20
#define NEL			21

static char *file_paths[NEL];
static char *file_suffixes[NEL] = {
	NULL,					/* BASEDIR */
	NULL,					/* POLICYDIR */
	NULL,					/* BINPOLICY */
	"/contexts",				/* CONTEXTS_DIR */
	"/contexts/files/file_contexts",	/* FILE_CONTEXTS */
	"/contexts/files/homedir_template",	/* HOMEDIR_CONTEXTS */
	"/contexts/default_contexts",		/* DEFAULT_CONTEXTS */
	"/contexts/users/",			/* USER_CONTEXTS */
	"/contexts/failsafe_context",		/* FAILSAFE_CONTEXT */
	"/contexts/default_type",		/* DEFAULT_TYPE */
	"/booleans",				/* BOOLEANS */
	"/contexts/files/media",		/* MEDIA_CONTEXTS */
	"/contexts/removable_context",		/* REMOVABLE_CONTEXT */
	"/contexts/customizable_types",		/* CUSTOMIZABLE_TYPES */
	"/users/",				/* USERS_DIR */
	"/seusers",				/* SEUSERS */
	"/setrans.conf",			/* TRANSLATIONS */
	"/contexts/netfilter_contexts",		/* NETFILTER_CONTEXTS */
	"/contexts/files/file_contexts.homedir",/* FILE_CONTEXTS_HOMEDIR */
	"/contexts/files/file_contexts.local",	/* FILE_CONTEXTS_LOCAL */
	"/contexts/securetty_types",		/* SECURETTY_TYPES */
};

static void sebsd_config_ctor(void) __attribute__ ((constructor));
static void sebsd_config_dtor(void) __attribute__ ((destructor));

static void
sebsd_config_ctor(void)
{
	char *path, *cp;
	int i, error;
	size_t len = 0;

	error = sysctlbyname("security.mac.sebsd.policypath",
	    NULL, &len, NULL, 0);
	if ((error != 0 && errno != ENOMEM) || len == 0) {
		/* sysctl failed, use hard-coded value */
		/* XXX - could check for unconfined_t to decide between
			 targeted and not. */
		path = strdup("/etc/security/sebsd/targeted/policy/policy.20");
		if (path == NULL)
			return;
		len = strlen(path);
	} else {
		if ((path = malloc(len)) == NULL)
			return;
		error = sysctlbyname("security.mac.sebsd.policypath",
		    path, &len, NULL, 0);
		if (error != 0)
			goto eom;
		len--;			/* length should not include NUL */
	}

	/* BINPOLICY */
	for (cp = &path[len - 1]; cp >= path; cp--) {
		if (!isdigit((unsigned char)*cp) && *cp != '.') {
			*(cp + 1) = '\0';
			break;
		}
	}
	file_paths[BINPOLICY] = strdup(path);
	if (file_paths[BINPOLICY] == NULL)
		goto eom;

	/* POLICYDIR */
	for (; cp >= path; cp--) {
		if (*cp == '/') {
			*cp = '\0';
			break;
		}
	}
	file_paths[POLICYDIR] = strdup(path);
	if (file_paths[POLICYDIR] == NULL)
		goto eom;

	/* BASEDIR */
	for (; cp >= path; cp--) {
		if (*cp == '/') {
			*cp = '\0';
			break;
		}
	}
	file_paths[BASEDIR] = strdup(path);
	if (file_paths[BASEDIR] == NULL)
		goto eom;

	free(path);
	path = NULL;

	/* Fill in the rest of file_paths. */
	for (i = 0; i < NEL; i++) {
		if (file_suffixes[i] != NULL) {
			if (asprintf(&file_paths[i], "%s%s", file_paths[BASEDIR],
			    file_suffixes[i]) == -1)
				goto eom;
		}
	}

	return;
eom:
	free(path);
	sebsd_config_dtor();
	return;
}

static void
sebsd_config_dtor(void)
{
	int i;

	for (i = 0; i < NEL; i++) {
		free(file_paths[i]);
		file_paths[i] = NULL;
	}
}

int
selinux_getenforcemode(int *enforce)
{
	int i, error;
	size_t isize = sizeof(i);

	error = sysctlbyname("security.mac.sebsd.enforcing", &i,
	    &isize, NULL, 0);
	*enforce = error ? -1 : i;
	return (error);
}

const char *
selinux_default_type_path(void)
{
	return (file_paths[DEFAULT_TYPE]);
}
hidden_def(selinux_default_type_path)

const char *
selinux_policy_root(void)
{
	return (file_paths[POLICYDIR]);
}

const char *
selinux_path(void)
{
	return (file_paths[BASEDIR]);
}
hidden_def(selinux_path)

const char *
selinux_default_context_path(void)
{
	return (file_paths[DEFAULT_CONTEXTS]);
}
hidden_def(selinux_default_context_path)

const char *
selinux_securetty_types_path(void)
{
	return (file_paths[SECURETTY_TYPES]);
}
hidden_def(selinux_securetty_types_path)

const char *
selinux_failsafe_context_path(void)
{
	return (file_paths[FAILSAFE_CONTEXT]);
}
hidden_def(selinux_failsafe_context_path)

const char *
selinux_removable_context_path(void)
{
	return (file_paths[REMOVABLE_CONTEXT]);
}
hidden_def(selinux_removable_context_path)

const char *
selinux_binary_policy_path(void)
{
	return (file_paths[BINPOLICY]);
}
hidden_def(selinux_binary_policy_path)

const char *
selinux_file_context_path(void)
{
	return (file_paths[FILE_CONTEXTS]);
}
hidden_def(selinux_file_context_path)

const char *
selinux_homedir_context_path(void)
{
	return (file_paths[HOMEDIR_CONTEXTS]);
}
hidden_def(selinux_homedir_context_path)

const char *
selinux_media_context_path(void)
{
	return (file_paths[MEDIA_CONTEXTS]);
}
hidden_def(selinux_media_context_path)

const char *
selinux_customizable_types_path(void)
{
	return (file_paths[CUSTOMIZABLE_TYPES]);
}
hidden_def(selinux_customizable_types_path)

const char *
selinux_contexts_path(void)
{
	return (file_paths[CONTEXTS_DIR]);
}

const char *
selinux_user_contexts_path(void)
{
	return (file_paths[USER_CONTEXTS]);
}
hidden_def(selinux_user_contexts_path)

const char *
selinux_booleans_path(void)
{
	return (file_paths[BOOLEANS]);
}
hidden_def(selinux_booleans_path)

const char *
selinux_users_path(void)
{
	return (file_paths[USERS_DIR]);
}
hidden_def(selinux_users_path)

const char *
selinux_usersconf_path(void)
{
	return (file_paths[SEUSERS]);
}
hidden_def(selinux_usersconf_path)

const char *
selinux_translations_path()
{
	return (file_paths[TRANSLATIONS]);
}
hidden_def(selinux_translations_path)

const char *selinux_netfilter_context_path()
{
	return (file_paths[NETFILTER_CONTEXTS]);
}
hidden_def(selinux_netfilter_context_path)

const char *selinux_file_context_homedir_path()
{
	return (file_paths[FILE_CONTEXTS_HOMEDIR]);
}
hidden_def(selinux_file_context_homedir_path)

const char *selinux_file_context_local_path()
{
	return (file_paths[FILE_CONTEXTS_LOCAL]);
}
hidden_def(selinux_file_context_local_path)
