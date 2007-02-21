/************************************************************************
 *
 * newrole
 *
 * SYNOPSIS:
 *
 * This program allows a user to change their SELinux RBAC role and/or
 * SELinux TE type (domain) in a manner similar to the way the traditional
 * UNIX su program allows a user to change their identity.
 *
 * USAGE:
 *
 * newrole [ -r role ] [ -t type ] [ -l level ] [ -V ] [ -- args ]
 *
 * BUILD OPTIONS:
 *
 * option USE_PAM:
 *
 * Set the USE_PAM constant if you want to authenticate users via PAM.
 * If USE_PAM is not set, users will be authenticated via direct
 * access to the shadow password file.
 *
 * If you decide to use PAM must be told how to handle newrole.  A
 * good rule-of-thumb might be to tell PAM to handle newrole in the
 * same way it handles su, except that you should remove the pam_rootok.so
 * entry so that even root must re-authenticate to change roles. 
 *
 * If you choose not to use PAM, make sure you have a shadow passwd file
 * in /etc/shadow.  You can use a symlink if your shadow passwd file
 * lives in another directory.  Example:
 *   su
 *   cd /etc
 *   ln -s /etc/auth/shadow shadow
 *
 * If you decide not to use PAM, you will also have to make newrole
 * setuid root, so that it can read the shadow passwd file.
 * 
 *
 * Authors:
 *      Anthony Colatrella
 *	Tim Fraser
 *	Steve Grubb <sgrubb@redhat.com>
 *	Darrel Goeddel <DGoeddel@trustedcs.com>
 *	Michael Thompson <mcthomps@us.ibm.com>
 *	Dan Walsh <dwalsh@redhat.com>
 *
 *************************************************************************/

#define _GNU_SOURCE

#if defined(AUDIT_LOG_PRIV) && !defined(USE_AUDIT)
#error AUDIT_LOG_PRIV needs the USE_AUDIT option
#endif
#if defined(NAMESPACE_PRIV) && !defined(USE_PAM)
#error NAMESPACE_PRIV needs the USE_PAM option
#endif

#include <stdio.h>
#include <stdlib.h>		/* for malloc(), realloc(), free() */
#include <pwd.h>		/* for getpwuid() */
#include <sys/types.h>		/* to make getuid() and getpwuid() happy */
#include <sys/wait.h>		/* for wait() */
#include <getopt.h>		/* for getopt_long() form of getopt() */
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>	/* for is_selinux_enabled() */
#include <selinux/flask.h>	/* for SECCLASS_CHR_FILE */
#include <selinux/context.h>	/* for context-mangling functions */
#include <selinux/get_default_type.h>
#include <selinux/get_context_list.h>	/* for SELINUX_DEFAULTUSER */
#include <sys/mac.h>
#include <signal.h>
#include <unistd.h>		/* for getuid(), exit(), getopt() */
#ifdef USE_AUDIT
#include <libaudit.h>
#endif
#if defined(AUDIT_LOG_PRIV) || (NAMESPACE_PRIV)
#include <sys/prctl.h>
#include <sys/capability.h>
#endif
#ifdef USE_NLS
#include <locale.h>		/* for setlocale() */
#include <libintl.h>		/* for gettext() */
#define _(msgid) gettext (msgid)
#else
#define _(msgid) (msgid)
#endif
#ifndef PACKAGE
#define PACKAGE "policycoreutils"	/* the name of this package lang translation */
#endif

/* USAGE_STRING describes the command-line args of this program. */
#define USAGE_STRING "USAGE: newrole [ -r role ] [ -t type ] [ -l level ] [ -p ] [ -V ] [ -- args ]"

#define DEFAULT_PATH "/usr/bin:/bin"
#define DEFAULT_CONTEXT_SIZE 255	/* first guess at context size */

extern char **environ;

/**
 * Construct from the current range and specified desired level a resulting
 * range. If the specified level is a range, return that. If it is not, then
 * construct a range with level as the sensitivity and clearance of the current
 * context.
 *
 * newlevel - the level specified on the command line
 * range    - the range in the current context
 *
 * Returns malloc'd memory
 */
static char *build_new_range(char *newlevel, const char *range)
{
	char *newrangep = NULL;
	const char *tmpptr;
	size_t len;

	/* a missing or empty string */
	if (!range || !strlen(range) || !newlevel || !strlen(newlevel))
		return NULL;

	/* if the newlevel is actually a range - just use that */
	if (strchr(newlevel, '-')) {
		newrangep = strdup(newlevel);
		return newrangep;
	}

	/* look for MLS range in current context */
	tmpptr = strchr(range, '-');
	if (tmpptr) {
		/* we are inserting into a ranged MLS context */
		len = strlen(newlevel) + 1 + strlen(tmpptr + 1) + 1;
		newrangep = (char *)malloc(len);
		if (!newrangep)
			return NULL;
		snprintf(newrangep, len, "%s-%s", newlevel, tmpptr + 1);
	} else {
		/* we are inserting into a currently non-ranged MLS context */
		if (!strcmp(newlevel, range)) {
			newrangep = strdup(range);
		} else {
			len = strlen(newlevel) + 1 + strlen(range) + 1;
			newrangep = (char *)malloc(len);
			if (!newrangep)
				return NULL;
			snprintf(newrangep, len, "%s-%s", newlevel, range);
		}
	}

	return newrangep;
}

#ifdef USE_PAM

/************************************************************************
 *
 * All PAM code goes in this section.
 *
 ************************************************************************/
#include <security/pam_appl.h>	/* for PAM functions */
#include <security/openpam.h>

#define SERVICE_NAME "newrole"	/* the name of this program for PAM */

/* authenticate_via_pam()
 *
 * in:     pw - struct containing data from our user's line in 
 *                         the passwd file.
 * out:    nothing
 * return: value   condition
 *         -----   ---------
 *           1     PAM thinks that the user authenticated themselves properly
 *           0     otherwise
 *
 * This function uses PAM to authenticate the user running this
 * program.  This is the only function in this program that makes PAM
 * calls.
 */
int authenticate_via_pam(const char *ttyn, pam_handle_t *pam_handle)
{

	int result = 0;		/* set to 0 (not authenticated) by default */
	int pam_rc;		/* pam return code */
	const char *tty_name;

	if (strncmp(ttyn, "/dev/", 5) == 0)
		tty_name = ttyn + 5;
	else
		tty_name = ttyn;

	pam_rc = pam_set_item(pam_handle, PAM_TTY, tty_name);
	if (pam_rc != PAM_SUCCESS) {
		fprintf(stderr, _("failed to set PAM_TTY\n"));
		goto out;
	}

	/* Ask PAM to authenticate the user running this program */
	pam_rc = pam_authenticate(pam_handle, 0);
	if (pam_rc != PAM_SUCCESS) {
		goto out;
	}

	/* Ask PAM to verify acct_mgmt */
	pam_rc = pam_acct_mgmt(pam_handle, 0);
	if (pam_rc == PAM_SUCCESS) {
		result = 1;	/* user authenticated OK! */
	}

      out:
	return result;
}				/* authenticate_via_pam() */

#else				/* else !USE_PAM */

/************************************************************************
 *
 * All shadow passwd code goes in this section.
 *
 ************************************************************************/
#include <shadow.h>		/* for shadow passwd functions */
#include <string.h>		/* for strlen(), memset() */

#define PASSWORD_PROMPT _("Password:")	/* prompt for getpass() */

/* authenticate_via_shadow_passwd()
 *
 * in:     uname - the calling user's user name
 * out:    nothing
 * return: value   condition
 *         -----   ---------
 *           1     user authenticated themselves properly according to the
 *                 shadow passwd file.
 *           0     otherwise
 *
 * This function uses the shadow passwd file to thenticate the user running
 * this program.
 */
int authenticate_via_shadow_passwd(const char *uname)
{
	struct spwd *p_shadow_line;
	char *unencrypted_password_s;
	char *encrypted_password_s;

	setspent();
	p_shadow_line = getspnam(uname);
	endspent();
	if (!(p_shadow_line)) {
		fprintf(stderr, _("Cannot find your entry in the shadow "
			"passwd file.\n"));
		return 0;
	}

	/* Ask user to input unencrypted password */
	if (!(unencrypted_password_s = getpass(PASSWORD_PROMPT))) {
		fprintf(stderr, _("getpass cannot open /dev/tty\n"));
		return 0;
	}

	/* Use crypt() to encrypt user's input password. */
	encrypted_password_s = crypt(unencrypted_password_s,
				     p_shadow_line->sp_pwdp);
	memset(unencrypted_password_s, 0, strlen(unencrypted_password_s));
	return (!strcmp(encrypted_password_s, p_shadow_line->sp_pwdp));
}
#endif				/* if/else USE_PAM */

/**
 * This function checks to see if the shell is known in /etc/shells.
 * If so, it returns 1. On error or illegal shell, it returns 0.
 */
static int verify_shell(const char *shell_name)
{
	int found = 0;
	const char *buf;

	if (! (shell_name && shell_name[0]))
		return found;

	while ((buf = getusershell()) != NULL) {
		/* ignore comments */
		if (*buf == '#')
			continue;

		/* check the shell skipping newline char */
		if (!strcmp(shell_name, buf)) {
			found = 1;
			break;
		}
	}
	endusershell();
	return found;
}

/**
 * Determine the Linux user identity to re-authenticate.
 * If supported and set, use the login uid, as this should be more stable.
 * Otherwise, use the real uid.
 *
 * This function assigns malloc'd memory into the pw_copy struct.
 * Returns zero on success, non-zero otherwise
 */
int extract_pw_data(struct passwd *pw_copy)
{
	uid_t uid;
	struct passwd *pw;

#ifdef USE_AUDIT
	uid = audit_getloginuid();
	if (uid == (uid_t) - 1)
		uid = getuid();
#else
	uid = getuid();
#endif

	setpwent();
	pw = getpwuid(uid);
	endpwent();
	if (!(pw && pw->pw_name && pw->pw_name[0] && pw->pw_shell
	      && pw->pw_shell[0] && pw->pw_dir && pw->pw_dir[0])) {
		fprintf(stderr,
			_("cannot find valid entry in the passwd file.\n"));
		return -1;
	}

	*pw_copy = *pw;
	pw = pw_copy;
	pw->pw_name = strdup(pw->pw_name);
	pw->pw_dir = strdup(pw->pw_dir);
	pw->pw_shell = strdup(pw->pw_shell);

	if (! (pw->pw_name && pw->pw_dir && pw->pw_shell)) {
		fprintf(stderr, _("Out of memory!\n"));
		goto out_free;
	}

	if (verify_shell(pw->pw_shell) == 0) {
		fprintf(stderr, _("Error!  Shell is not valid.\n"));
		goto out_free;
	}
	return 0;

out_free:
	free(pw->pw_name);
	free(pw->pw_dir);
	free(pw->pw_shell);
	return -1;
}

/**
 * Either restore the original environment, or set up a minimal one.
 *
 * The minimal environment contains:
 * TERM, DISPLAY and XAUTHORITY - if they are set, preserve values
 * HOME, SHELL, USER and LOGNAME - set to contents of /etc/passwd
 * PATH - set to default value DEFAULT_PATH
 *
 * Returns zero on success, non-zero otherwise
 */
static int restore_environment(int preserve_environment,
			       char **old_environ, const struct passwd *pw)
{
	char const *term_env;
	char const *display_env;
	char const *xauthority_env;
	char *term = NULL;		/* temporary container */
	char *display = NULL;		/* temporary container */
	char *xauthority = NULL;	/* temporary container */
	int rc;

	environ = old_environ;

	if (preserve_environment)
		return 0;

	term_env = getenv("TERM");
	display_env = getenv("DISPLAY");
	xauthority_env = getenv("XAUTHORITY");

	/* Save the variable values we want */
	if (term_env)
		term = strdup(term_env);
	if (display_env)
		display = strdup(display_env);
	if (xauthority_env)
		xauthority = strdup(xauthority_env);
	if ((term_env && !term) || (display_env && !display) ||
	     (xauthority_env && !xauthority)) {
		rc = -1;
		goto out;
	}

	/* Construct a new environment */
	if ((rc = clearenv())) {
		fprintf(stderr, _("Unable to clear environment\n"));
		goto out;
	}

	/* Restore that which we saved */
	if (term)
		rc |= setenv("TERM", term, 1);
	if (display)
		rc |= setenv("DISPLAY", display, 1);
	if (xauthority)
		rc |= setenv("XAUTHORITY", xauthority, 1);
	rc |= setenv("HOME", pw->pw_dir, 1);
	rc |= setenv("SHELL", pw->pw_shell, 1);
	rc |= setenv("USER", pw->pw_name, 1);
	rc |= setenv("LOGNAME", pw->pw_name, 1);
	rc |= setenv("PATH", DEFAULT_PATH, 1);
out:
	free(term);
	free(display);
	free(xauthority);
	return rc;
}

/**
 * This function will drop the capabilities so that we are left
 * only with access to the audit system. If the user is root, we leave
 * the capabilities alone since they already should have access to the
 * audit netlink socket.
 *
 * Returns zero on success, non-zero otherwise
 */
#if defined(AUDIT_LOG_PRIV) && !defined(NAMESPACE_PRIV)
static int drop_capabilities(void)
{
	int rc = 0;
	cap_t new_caps, tmp_caps;
	cap_value_t cap_list[] = { CAP_AUDIT_WRITE };
	cap_value_t tmp_cap_list[] = { CAP_AUDIT_WRITE, CAP_SETUID };
	uid_t uid = getuid();

	if (!uid)
		return 0;

	/* Non-root caller, suid root path */
	new_caps = cap_init();
	tmp_caps = cap_init();
	if (!new_caps || !tmp_caps) {
		fprintf(stderr, _("Error initing capabilities, aborting.\n"));
		return -1;
	}
	rc |= cap_set_flag(new_caps, CAP_PERMITTED, 1, cap_list, CAP_SET);
	rc |= cap_set_flag(new_caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET);
	rc |= cap_set_flag(tmp_caps, CAP_PERMITTED, 2, tmp_cap_list, CAP_SET);
	rc |= cap_set_flag(tmp_caps, CAP_EFFECTIVE, 2, tmp_cap_list, CAP_SET);
	if (rc) {
		fprintf(stderr, _("Error setting capabilities, aborting\n"));
		goto out;
	}

	/* Keep capabilities across uid change */
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
		fprintf(stderr, _("Error setting KEEPCAPS, aborting\n"));
		rc = -1;
		goto out;
	}

	/* Does this temporary change really buy us much? */
	/* We should still have root's caps, so drop most capabilities now */
	if ((rc = cap_set_proc(tmp_caps))) {
		fprintf(stderr, _("Error dropping capabilities, aborting\n"));
		goto out;
	}

	/* Change uid */
	if ((rc = setresuid(uid, uid, uid))) {
		fprintf(stderr, _("Error changing uid, aborting.\n"));
		goto out;
	}

	/* Now get rid of this ability */
	if ((rc = prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) < 0)) {
		fprintf(stderr, _("Error resetting KEEPCAPS, aborting\n"));
		goto out;
	}

	/* Finish dropping capabilities. */
	if ((rc = cap_set_proc(new_caps))) {
		fprintf(stderr,
			_("Error dropping SETUID capability, aborting\n"));
		goto out;
	}
out:
	if (cap_free(tmp_caps) || cap_free(new_caps))
		fprintf(stderr, _("Error freeing caps\n"));
	return rc;
}
#elif defined(NAMESPACE_PRIV)
/**
 * This function will drop the capabilities so that we are left
 * only with access to the audit system and the ability to raise
 * CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_FOWNER and CAP_CHOWN,
 * before invoking pam_namespace.  These capabilities are needed
 * for performing bind mounts/unmounts and to create potential new
 * instance directories with appropriate DAC attributes. If the
 * user is root, we leave the capabilities alone since they already
 * should have access to the audit netlink socket and should have
 * the ability to create/mount/unmount instance directories.
 *
 * Returns zero on success, non-zero otherwise
 */
static int drop_capabilities(void)
{
	int rc = 0;
	cap_t new_caps;
	cap_value_t cap_list[] = { CAP_AUDIT_WRITE, CAP_SETUID,
				   CAP_SYS_ADMIN, CAP_FOWNER, CAP_CHOWN,
				   CAP_DAC_OVERRIDE };

	if (!getuid())
		return 0;

	/* Non-root caller, suid root path */
	new_caps = cap_init();
	if (!new_caps) {
		fprintf(stderr, _("Error initing capabilities, aborting.\n"));
		return -1;
	}
	rc |= cap_set_flag(new_caps, CAP_PERMITTED, 6, cap_list, CAP_SET);
	rc |= cap_set_flag(new_caps, CAP_EFFECTIVE, 6, cap_list, CAP_SET);
	if (rc) {
		fprintf(stderr, _("Error setting capabilities, aborting\n"));
		goto out;
	}

	/* Ensure that caps are dropped after setuid call */
	if ((rc = prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) < 0)) {
		fprintf(stderr, _("Error resetting KEEPCAPS, aborting\n"));
		goto out;
	}

	/* We should still have root's caps, so drop most capabilities now */
	if ((rc = cap_set_proc(new_caps))) {
		fprintf(stderr, _("Error dropping capabilities, aborting\n"));
		goto out;
	}
out:
	if (cap_free(new_caps))
		fprintf(stderr, _("Error freeing caps\n"));
	return rc;
}

#else
static inline int drop_capabilities(void)
{
	return 0;
}
#endif

#ifdef NAMESPACE_PRIV
/**
 * This function will set the uid values to be that of caller's uid, and
 * will drop any privilages which maybe have been raised.
 */
static int transition_to_caller_uid()
{
	uid_t uid = getuid();

	if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) < 0) {
		fprintf(stderr, _("Error resetting KEEPCAPS, aborting\n"));
		return -1;
	}

	if (setresuid(uid, uid, uid)) {
		fprintf(stderr, _("Error changing uid, aborting.\n"));
		return -1;
	}
	return 0;
}
#endif

#ifdef AUDIT_LOG_PRIV
/* Send audit message */
static
int send_audit_message(int success, security_context_t old_context,
		       security_context_t new_context, const char *ttyn)
{
	char *msg = NULL;
	int rc;
	int audit_fd = audit_open();

	if (audit_fd < 0) {
		fprintf(stderr, _("Error connecting to audit system.\n"));
		return -1;
	}
	if (asprintf(&msg, "newrole: old-context=%s new-context=%s",
		     old_context ? old_context : "?",
		     new_context ? new_context : "?") < 0) {
		fprintf(stderr, _("Error allocating memory.\n"));
		rc = -1;
		goto out;
	}
	rc = audit_log_user_message(audit_fd, AUDIT_USER_ROLE_CHANGE,
				    msg, NULL, NULL, ttyn, success);
	if (rc <= 0) {
		fprintf(stderr, _("Error sending audit message.\n"));
		rc = -1;
		goto out;
	}
	rc = 0;
      out:
	free(msg);
	close(audit_fd);
	return rc;
}
#else
static inline
    int send_audit_message(int success __attribute__ ((unused)),
			   security_context_t old_context
			   __attribute__ ((unused)),
			   security_context_t new_context
			   __attribute__ ((unused)), const char *ttyn
			   __attribute__ ((unused)))
{
	return 0;
}
#endif

/**
 * This function attempts to relabel the tty. If this function fails, then
 * the fd is closed, the contexts are free'd and -1 is returned. On success,
 * a valid fd is returned and tty_context and new_tty_context are set.
 *
 * This function will not fail if it can not relabel the tty when selinux is
 * in permissive mode.
 */
static int relabel_tty(const char *ttyn, security_context_t new_context,
			security_context_t *tty_context,
			security_context_t *new_tty_context)
{
	int fd;
	int enforcing = security_getenforce();
	security_context_t tty_con = NULL;
	security_context_t new_tty_con = NULL;

	if (enforcing < 0) {
		fprintf(stderr, _("Could not determine enforcing mode.\n"));
		return -1;
	}

	/* Re-open TTY descriptor */
	fd = open(ttyn, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, _("Error!  Could not open %s.\n"), ttyn);
		return fd;
	}

	if (fgetfilecon(fd, &tty_con) < 0) {
		fprintf(stderr, _("%s!  Could not get current context "
			"for %s, not relabeling tty.\n"),
			enforcing ? "Error" : "Warning", ttyn);
		if (enforcing)
			goto close_fd;
	}

	if (tty_con &&
	    (security_compute_relabel(new_context, tty_con,
				      SECCLASS_CHR_FILE, &new_tty_con) < 0)) {
		fprintf(stderr,	_("%s!  Could not get new context for %s, "
			"not relabeling tty.\n"),
			enforcing ? "Error" : "Warning", ttyn);
		if (enforcing)
			goto close_fd;
	}

	if (new_tty_con)
		if (fsetfilecon(fd, new_tty_con) < 0) {
			fprintf(stderr,
				_("%s!  Could not set new context for %s\n"),
				enforcing ? "Error" : "Warning", ttyn);
			freecon(new_tty_con);
			new_tty_con = NULL;
			if (enforcing)
				goto close_fd;
		}

	*tty_context = tty_con;
	*new_tty_context = new_tty_con;
	return fd;

close_fd:
	freecon(tty_con);
	close(fd);
	return -1;
}

/**
 * This function attempts to revert the relabeling done to the tty.
 * fd   - referencing the opened ttyn
 * ttyn - name of tty to restore
 * tty_context     - original context of the tty
 * new_tty_context - context tty was relabeled to
 *
 * Returns zero on success, non-zero otherwise
 */
static int restore_tty_label(int fd, const char *ttyn,
			     security_context_t tty_context,
			     security_context_t new_tty_context)
{
	int rc = 0;
	security_context_t chk_tty_context = NULL;

	if (!new_tty_context)
		goto skip_relabel;

	/* Verify that the tty still has the context set by newrole. */
	if ((rc = fgetfilecon(fd, &chk_tty_context)) < 0) {
		fprintf(stderr, "Could not fgetfilecon %s.\n", ttyn);
		goto skip_relabel;
	}

	if ((rc = strcmp(chk_tty_context, new_tty_context))) {
		fprintf(stderr, _("%s changed labels.\n"), ttyn);
		goto skip_relabel;
	}

	if ((rc = fsetfilecon(fd, tty_context)) < 0)
		fprintf(stderr,
			_("Warning! Could not restore context for %s\n"), ttyn);
skip_relabel:
	freecon(chk_tty_context);
	return rc;
}

/**
 * Parses and validates the provided command line options and
 * constructs a new context based on our old context and the
 * arguments specified on the command line. On success
 * new_context will be set to valid values, otherwise its value
 * is left unchanged.
 *
 * Returns zero on success, non-zero otherwise.
 */
static int parse_command_line_arguments(int argc, char **argv, char *ttyn,
					security_context_t old_context,
					security_context_t *new_context,
					int *preserve_environment)
{
	int flag_index;		/* flag index in argv[] */
	int clflag;		/* holds codes for command line flags */
	char *role_s = NULL;	/* role spec'd by user in argv[] */
	char *type_s = NULL;	/* type spec'd by user in argv[] */
	char *type_ptr = NULL;	/* stores malloc'd data from get_default_type */
	char *level_s = NULL;	/* level spec'd by user in argv[] */
	char *range_ptr = NULL;
	security_context_t new_con = NULL;
	security_context_t tty_con = NULL;
	context_t context = NULL; /* manipulatable form of new_context */
	const struct option long_options[] = {
		{"role", 1, 0, 'r'},
		{"type", 1, 0, 't'},
		{"level", 1, 0, 'l'},
		{"preserve-environment", 0, 0, 'p'},
		{"version", 0, 0, 'V'},
		{NULL, 0, 0, 0}
	};

	*preserve_environment = 0;
	while (1) {
		clflag = getopt_long(argc, argv, "r:t:l:pV", long_options,
				     &flag_index);
		if (clflag == -1)
			break;

		switch (clflag) {
		case 'V':
			printf("newrole: %s version %s\n", PACKAGE, VERSION);
			exit(0);
			break;
		case 'p':
			*preserve_environment = 1;
			break;
		case 'r':
			if (role_s) {
				fprintf(stderr,
					_("Error: multiple roles specified\n"));
				return -1;
			}
			role_s = optarg;
			break;
		case 't':
			if (type_s) {
				fprintf(stderr,
					_("Error: multiple types specified\n"));
				return -1;
			}
			type_s = optarg;
			break;
		case 'l':
			if (!is_selinux_mls_enabled()) {
				fprintf(stderr, _("Sorry, -l may be used with "
					"SELinux MLS support.\n"));
				return -1;
			}
			if (level_s) {
				fprintf(stderr, _("Error: multiple levels "
					"specified\n"));
				return -1;
			}
			if (fgetfilecon(0,&tty_con) >= 0) {
				if (selinux_check_securetty_context(tty_con) < 0) {
					fprintf(stderr, _("Error: you are not allowed to change levels on a non secure terminal\n"));
					freecon(tty_con);
					return -1;
				}
				freecon(tty_con);
			}

			level_s = optarg;
			break;
		default:
			fprintf(stderr, "%s\n", USAGE_STRING);
			return -1;
		}
	}

	/* Verify that the combination of command-line arguments are viable */
	if (!(role_s || type_s || level_s)) {
		fprintf(stderr, "%s\n", USAGE_STRING);
		return -1;
	}

	/* Fill in a default type if one hasn't been specified. */
	if (role_s && !type_s) {
	 	/* get_default_type() returns malloc'd memory */
		if (get_default_type(role_s, &type_ptr)) {
			fprintf(stderr, _("Couldn't get default type.\n"));
			send_audit_message(0, old_context, new_con, ttyn);
			return -1;
		}
		type_s = type_ptr;
	}

	/* Create a temporary new context structure we extract and modify */
	context = context_new(old_context);
	if (!context) {
		fprintf(stderr, _("failed to get new context.\n"));
		goto err_free;
	}

	/* Modify the temporary new context */
	if (role_s)
		if (context_role_set(context, role_s)) {
			fprintf(stderr, _("failed to set new role %s\n"),
				role_s);
			goto err_free;
		}

	if (type_s)
		if (context_type_set(context, type_s)) {
			fprintf(stderr, _("failed to set new type %s\n"),
				type_s);
			goto err_free;
		}

	if (level_s) {
		range_ptr = build_new_range(level_s,context_range_get(context));
		if (!range_ptr) {
			fprintf(stderr,
				_("failed to build new range with level %s\n"),
				level_s);
			goto err_free;
		}
		if (context_range_set(context, range_ptr)) {
			fprintf(stderr, _("failed to set new range %s\n"),
				range_ptr);
			goto err_free;
		}
	}

	/* Construct the final new context */
	if (!(new_con = context_str(context))) {
		fprintf(stderr, _("failed to convert new context to string\n"));
		goto err_free;
	}

	if (security_check_context(new_con) < 0) {
		fprintf(stderr, _("%s is not a valid context\n"), new_con);
		send_audit_message(0, old_context, new_con, ttyn);
		goto err_free;
	}

	*new_context = strdup(new_con);
	if (!*new_context) {
		fprintf(stderr, _("Unable to allocate memory for new_context"));
		goto err_free;
	}

	free(type_ptr);
	free(range_ptr);
	context_free(context);
	return 0;

err_free:
	free(type_ptr);
	free(range_ptr);
	/* Don't free new_con, context_free(context) handles this */
	context_free(context);
	return -1;
}

/**
 * Take care of any signal setup
 */
static int set_signal_handles()
{
	sigset_t empty;

	/* Empty the signal mask in case someone is blocking a signal */
	if (sigemptyset(&empty)) {
		fprintf(stderr, _("Unable to obtain empty signal set\n"));
		return -1;
	}

	(void)sigprocmask(SIG_SETMASK, &empty, NULL);

	/* Terminate on SIGHUP. */
	if (signal(SIGHUP, SIG_DFL) == SIG_ERR) {
		fprintf(stderr, _("Unable to set SIGHUP handler\n"));
		return -1;
	}

	return 0;
}

/************************************************************************
 *
 * All code used for both PAM and shadow passwd goes in this section.
 *
 ************************************************************************/

int main(int argc, char *argv[])
{
	security_context_t new_context = NULL;	/* target security context */
	security_context_t old_context = NULL;	/* original securiy context */
	security_context_t tty_context = NULL;	/* current context of tty */
	security_context_t new_tty_context = NULL; /* new context of tty */

	struct passwd pw;	/* struct derived from passwd file line */
	char *ttyn = NULL;	/* tty path */

	char **old_environ;
	int preserve_environment;

	int fd;
	pid_t childPid = 0;
	char *shell_argv0 = NULL;

	char *labeltext;
	mac_t label;

#ifdef USE_PAM
	int rc;
	int pam_status;		   /* pam return code */
	pam_handle_t *pam_handle;  /* opaque handle used by all PAM functions */

	/* This is a jump table of functions for PAM to use when it wants to *
	 * communicate with the user.  We'll be using openpam_ttyconv(),     *
	 * which is provided for us via openpam.h.                           */
	struct pam_conv pam_conversation = {
		openpam_ttyconv,
		NULL
	};
#endif

	/*
	 * Step 0: Setup
	 *
	 * Do some intial setup, including dropping capabilities, checking
	 * if it makes sense to continue to run newrole, and setting up
	 * a scrubbed environment.
	 */
	if (drop_capabilities())
		return -1;
	if (set_signal_handles())
		return -1;

#ifdef USE_NLS
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif

	old_environ = environ;
	environ = NULL;

	if (!is_selinux_enabled()) {
		fprintf(stderr, _("Sorry, newrole may be used only on "
			"a SELinux kernel.\n"));
		return -1;
	}

	if (security_getenforce() < 0) {
		fprintf(stderr, _("Could not determine enforcing mode.\n"));
		return -1;
	}

	/*
	 * Step 1: Parse command line and valid arguments
	 *
	 * old_context and ttyn are required for audit logging,
	 * context validation and pam
	 */
	if (getprevcon(&old_context)) {
		fprintf(stderr, _("failed to get old_context.\n"));
		return -1;
	}

	ttyn = ttyname(0);
	if (!ttyn || *ttyn == '\0') {
		fprintf(stderr,
			_("Error!  Could not retrieve tty information.\n"));
		return -1;
	}

	if (parse_command_line_arguments(argc, argv, ttyn, old_context,
					 &new_context, &preserve_environment))
		return -1;

	/*
	 * Step 2:  Authenticate the user.
	 *
	 * Re-authenticate the user running this program.
	 * This is just to help confirm user intent (vs. invocation by
	 * malicious software), not to authorize the operation (which is covered
	 * by policy).  Trusted path mechanism would be preferred.
	 */
	if (extract_pw_data(&pw))
		goto err_free;

	printf(_("Authenticating %s.\n"), pw.pw_name);
#ifdef USE_PAM
	pam_status = pam_start(SERVICE_NAME, pw.pw_name, &pam_conversation,
			       &pam_handle);
	if (pam_status != PAM_SUCCESS) {
		fprintf(stderr, _("failed to initialize PAM\n"));
		goto err_free;
	}

	if (!authenticate_via_pam(ttyn, pam_handle))
#else
	if (!authenticate_via_shadow_passwd(pw.pw_name))
#endif
	{
		fprintf(stderr, _("newrole: incorrect password for %s\n"),
			pw.pw_name);
		send_audit_message(0, old_context, new_context, ttyn);
		goto err_close_pam;
	}

	/*
	 * Step 3:  Handle relabeling of the tty.
	 *
	 * Once we authenticate the user, we know that we want to proceed with
	 * the action. Prior to this point, no changes are made the to system.
	 */
	fd = relabel_tty(ttyn, new_context, &tty_context, &new_tty_context);
	if (fd < 0)
		goto err_close_pam;

	/*
	 * Step 4: Fork
	 *
	 * Fork, allowing parent to clean up after shell has executed.
	 * Child: reopen stdin, stdout, stderr and exec shell
	 * Parnet: wait for child to die and restore tty's context
	 */
	childPid = fork();
	if (childPid < 0) {
		/* fork failed, no child to worry about */
		int errsv = errno;
		fprintf(stderr, _("newrole: failure forking: %s"),
			strerror(errsv));
		if (restore_tty_label(fd, ttyn, tty_context, new_tty_context))
			fprintf(stderr, _("Unable to restore tty label...\n"));
		if (close(fd))
			fprintf(stderr, _("Failed to close tty properly\n"));
		goto err_close_pam;
	} else if (childPid) {
		/* PARENT
		 * It doesn't make senes to exit early on errors at this point,
		 * since we are doing cleanup which needs to be done.
		 * We can exit with a bad rc though
		 */
		int rc;
		int exit_code = 0;
		int status;

		do {
			rc = wait(&status);
		} while (rc < 0 && errno == EINTR);

		/* Preserve child exit status, unless there is another error. */
		if (WIFEXITED(status))
			exit_code = WEXITSTATUS(status);

		if (restore_tty_label(fd, ttyn, tty_context, new_tty_context)) {
			fprintf(stderr, _("Unable to restore tty label...\n"));
			exit_code = -1;
		}
		freecon(tty_context);
		freecon(new_tty_context);
		if (close(fd)) {
			fprintf(stderr, _("Failed to close tty properly\n"));
			exit_code = -1;
		}
#ifdef USE_PAM
#ifdef NAMESPACE_PRIV
		pam_status = pam_close_session(pam_handle,0);
		if (pam_status != PAM_SUCCESS) {
			fprintf(stderr, "pam_close_session failed with %s\n",
				pam_strerror(pam_handle, pam_status));
			exit_code = -1;
		}
#endif
		rc = pam_end(pam_handle, pam_status);
		if (rc != PAM_SUCCESS) {
			fprintf(stderr, "pam_end failed with %s\n",
				pam_strerror(pam_handle, rc));
			exit_code = -1;
		}
#endif
		free(pw.pw_name);
		free(pw.pw_dir);
		free(pw.pw_shell);
		free(shell_argv0);
		return exit_code;
	}

	/* CHILD */
	/* Close the tty and reopen descriptors 0 through 2 */
	if (close(fd) || close(0) || close(1) || close(2)) {
		fprintf(stderr, _("Could not close descriptors.\n"));
		goto err_close_pam;
	}
	fd = open(ttyn, O_RDONLY);
	if (fd != 0)
		goto err_close_pam;
	fd = open(ttyn, O_RDWR);
	if (fd != 1)
		goto err_close_pam;
	fd = open(ttyn, O_RDWR);
	if (fd != 2)
		goto err_close_pam;

	/*
	 * Step 5:  Execute a new shell with the new context in `new_context'. 
	 *
	 * Establish context, namesapce and any options for the new shell
	 */
	if (optind < 1)
		optind = 1;

	/* This is ugly, but use newrole's argv for the exec'd shells argv */
	if (asprintf(&shell_argv0, "-%s", pw.pw_shell) < 0) {
		fprintf(stderr, _("Error allocating shell's argv0.\n"));
		shell_argv0 = NULL;
		goto err_close_pam;
	}
	argv[optind-1] = shell_argv0;

	if (asprintf(&labeltext, "sebsd/%s", new_context) == -1 ||
	    mac_from_text(&label, labeltext) != 0) {
		fprintf(stderr, _("Could not set exec context to %s.\n"),
			new_context);
		goto err_close_pam;
	}
	free(labeltext);

#ifdef NAMESPACE_PRIV
	/* Ask PAM to setup session for user running this program */
	pam_status = pam_open_session(pam_handle,0);
	if (pam_status != PAM_SUCCESS) {
		fprintf(stderr, "pam_open_session failed with %s\n",
			pam_strerror(pam_handle, pam_status));
		goto err_close_pam;
	}
#endif

	if (send_audit_message(1, old_context, new_context, ttyn))
		goto err_close_pam_session;
#ifdef NAMESPACE_PRIV
	if (transition_to_caller_uid())
		goto err_close_pam_session;
#endif

	freecon(old_context);
	freecon(new_context);

	/* Handle environment changes */
	if (restore_environment(preserve_environment, old_environ, &pw)) {
		fprintf(stderr, _("Unable to restore the environment, "
			"aborting\n"));
		goto err_close_pam_session;
	}
	mac_execve(pw.pw_shell, argv + optind - 1, environ, label);

	/*
	 * Error path cleanup
	 *
	 * If we reach here, then we failed to exec the new shell.
	 */
	perror(_("failed to exec shell\n"));
err_close_pam_session:
#ifdef NAMESPACE_PRIV
	pam_status = pam_close_session(pam_handle,0);
	if(pam_status != PAM_SUCCESS)
		fprintf(stderr, "pam_close_session failed with %s\n",
			pam_strerror(pam_handle, pam_status));
#endif
err_close_pam:
#ifdef USE_PAM
	rc = pam_end(pam_handle, pam_status);
	if (rc != PAM_SUCCESS)
		fprintf(stderr, "pam_end failed with %s\n",
			pam_strerror(pam_handle, rc));
#endif
err_free:
	freecon(tty_context);
	freecon(new_tty_context);
	freecon(old_context);
	freecon(new_context);
	free(pw.pw_name);
	free(pw.pw_dir);
	free(pw.pw_shell);
	free(shell_argv0);
	return -1;
}				/* main() */
