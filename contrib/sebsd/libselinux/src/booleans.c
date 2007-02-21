/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Modified:  
 *   Dan Walsh <dwalsh@redhat.com> - Added security_load_booleans().
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mac.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fnmatch.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include <selinux/selinux.h>
#include <selinux/secompat.h>
#include <security/sebsd/sebsd_syscalls.h>

#include "selinux_internal.h"

int security_get_boolean_names(char ***names, int *len)
{
	struct sebsd_get_bools gb;
	int i, err, num = 0, rc = -1;
	char **n, *p, *q, *buf, *ep;

	gb.out = NULL;
	gb.len = 0;

	err = mac_syscall("sebsd", SEBSDCALL_GET_BOOLS, &gb);
	if (err && errno != ENOMEM)
		return (-1);

	if ((buf = malloc(gb.len)) == NULL)
		return (-1);
	gb.out = buf;

	err = mac_syscall("sebsd", SEBSDCALL_GET_BOOLS, &gb);
	if (err)
		goto out;

	for (p = buf, ep = buf + gb.len; p < ep; p++)
		if (*p == ';')
			num++;

	n = (char **)malloc(sizeof(char *) * num);
	if (!n)
		goto out;

	p = buf;
	for (i = 0; i < num; i++) {
		p += 2;
		for (q = p; *q != ';'; q++)
			continue;

		n[i] = strndup(p, q - p);
		if (!n[i])
			goto bad;
		p = q + 1;
	}
	rc = 0;
	*names = n;
	*len = num;
	goto out;

bad:
	for (i = 0; i < *len; i++)
		free(n[i]);
	free(n);
out:
	free(buf);

	return rc;
}

hidden_def(security_get_boolean_names)

int security_get_boolean_pending(const char *name)
{
	int r;

	r = mac_syscall("sebsd", SEBSDCALL_GET_BOOL, (void *)name);
	if (r < 0)
		return -1;
	return (r & 2) >> 1;
}

int security_get_boolean_active(const char *name)
{
	int r;

	r = mac_syscall("sebsd", SEBSDCALL_GET_BOOL, (void *)name);
	if (r < 0)
		return -1;
	return (r & 1);
}

hidden_def(security_get_boolean_active)

int security_set_boolean(const char *name, int value)
{
	struct lp_args args;
	char str[strlen(name) + 2];

	str[0] = value + '0';
	strcpy (str+1, name);
	args.data = str;
	args.len = strlen(str) + 1;
	int err = mac_syscall("sebsd", SEBSDCALL_SET_BOOL, &args);
	if (err)
		perror (name);
	return err;
}

hidden_def(security_set_boolean)

int security_commit_booleans(void)
{
	return mac_syscall("sebsd", SEBSDCALL_COMMIT_BOOLS, NULL);
}

hidden_def(security_commit_booleans)

static char *strtrim(char *dest, char *source, int size)
{
	int i = 0;
	char *ptr = source;
	i = 0;
	while (isspace(*ptr) && i < size) {
		ptr++;
		i++;
	}
	strncpy(dest, ptr, size);
	for (i = strlen(dest) - 1; i > 0; i--) {
		if (!isspace(dest[i]))
			break;
	}
	dest[i + 1] = '\0';
	return dest;
}

static int process_boolean(char *buffer, char *name, int namesize, int *val)
{
	char name1[BUFSIZ];
	char *ptr;
	char *tok = strtok_r(buffer, "=", &ptr);
	if (tok) {
		strncpy(name1, tok, BUFSIZ - 1);
		strtrim(name, name1, namesize - 1);
		if (name[0] == '#')
			return 0;
		tok = strtok_r(NULL, "\0", &ptr);
		if (tok) {
			while (isspace(*tok))
				tok++;
			*val = -1;
			if (isdigit(tok[0]))
				*val = atoi(tok);
			else if (!strncasecmp(tok, "true", sizeof("true") - 1))
				*val = 1;
			else if (!strncasecmp
				 (tok, "false", sizeof("false") - 1))
				*val = 0;
			if (*val != 0 && *val != 1) {
				errno = EINVAL;
				return -1;
			}

		}
	}
	return 1;
}
static int save_booleans(size_t boolcnt, SELboolean * boollist)
{
	ssize_t len;
	size_t i;
	char outbuf[BUFSIZ];
	char *inbuf = NULL;

	/* Open file */
	const char *bool_file = selinux_booleans_path();
	char local_bool_file[PATH_MAX];
	char tmp_bool_file[PATH_MAX];
	FILE *boolf;
	int fd;
	int *used = (int *)malloc(sizeof(int) * boolcnt);
	if (!used) {
		return -1;
	}
	/* zero out used field */
	for (i = 0; i < boolcnt; i++)
		used[i] = 0;

	snprintf(tmp_bool_file, sizeof(tmp_bool_file), "%s.XXXXXX", bool_file);
	fd = mkstemp(tmp_bool_file);
	if (fd < 0) {
		free(used);
		return -1;
	}

	snprintf(local_bool_file, sizeof(local_bool_file), "%s.local",
		 bool_file);
	boolf = fopen(local_bool_file, "r");
	if (boolf != NULL) {
		ssize_t ret;
		size_t size = 0;
		int val;
		char boolname[BUFSIZ];
		char *buffer;
		inbuf = NULL;
		while ((len = getline(&inbuf, &size, boolf)) > 0) {
			buffer = strdup(inbuf);
			if (!buffer)
				goto close_remove_fail;
			ret =
			    process_boolean(inbuf, boolname, sizeof(boolname),
					    &val);
			if (ret != 1) {
				ret = write(fd, buffer, len);
				free(buffer);
				if (ret != len)
					goto close_remove_fail;
			} else {
				free(buffer);
				for (i = 0; i < boolcnt; i++) {
					if (strcmp(boollist[i].name, boolname)
					    == 0) {
						snprintf(outbuf, sizeof(outbuf),
							 "%s=%d\n", boolname,
							 boollist[i].value);
						len = strlen(outbuf);
						used[i] = 1;
						if (write(fd, outbuf, len) !=
						    len)
							goto close_remove_fail;
						else
							break;
					}
				}
				if (i == boolcnt) {
					snprintf(outbuf, sizeof(outbuf),
						 "%s=%d\n", boolname, val);
					len = strlen(outbuf);
					if (write(fd, outbuf, len) != len)
						goto close_remove_fail;
				}
			}
			free(inbuf);
			inbuf = NULL;
		}
		fclose(boolf);
	}

	for (i = 0; i < boolcnt; i++) {
		if (used[i] == 0) {
			snprintf(outbuf, sizeof(outbuf), "%s=%d\n",
				 boollist[i].name, boollist[i].value);
			len = strlen(outbuf);
			if (write(fd, outbuf, len) != len) {
			      close_remove_fail:
				free(inbuf);
				close(fd);
			      remove_fail:
				unlink(tmp_bool_file);
				free(used);
				return -1;
			}
		}

	}
	if (fchmod(fd, S_IRUSR | S_IWUSR) != 0)
		goto close_remove_fail;
	close(fd);
	if (rename(tmp_bool_file, local_bool_file) != 0)
		goto remove_fail;

	free(used);
	return 0;
}

static void rollback(SELboolean * boollist, int end)
{
	int i;

	for (i = 0; i < end; i++)
		security_set_boolean(boollist[i].name,
				     security_get_boolean_active(boollist[i].
								 name));
}

int security_set_boolean_list(size_t boolcnt, SELboolean * boollist,
			      int permanent)
{

	size_t i;
	for (i = 0; i < boolcnt; i++) {
		if (security_set_boolean(boollist[i].name, boollist[i].value)) {
			rollback(boollist, i);
			return -1;
		}
	}

	/* OK, let's do the commit */
	if (security_commit_booleans()) {
		return -1;
	}

	if (permanent)
		return save_booleans(boolcnt, boollist);

	return 0;
}

int security_load_booleans(char *path)
{
	FILE *boolf;
	char *inbuf;
	char localbools[BUFSIZ];
	size_t len = 0, errors = 0;
	int val;
	char name[BUFSIZ];

	boolf = fopen(path ? path : selinux_booleans_path(), "r");
	if (boolf == NULL)
		goto localbool;

	while (getline(&inbuf, &len, boolf) > 0) {
		int ret = process_boolean(inbuf, name, sizeof(name), &val);
		if (ret == -1)
			errors++;
		if (ret == 1)
			if (security_set_boolean(name, val) < 0) {
				errors++;
			}
	}
	fclose(boolf);
      localbool:
	snprintf(localbools, sizeof(localbools), "%s.local",
		 (path ? path : selinux_booleans_path()));
	boolf = fopen(localbools, "r");

	if (boolf != NULL) {
		int ret;
		while (getline(&inbuf, &len, boolf) > 0) {
			ret = process_boolean(inbuf, name, sizeof(name), &val);
			if (ret == -1)
				errors++;
			if (ret == 1)
				if (security_set_boolean(name, val) < 0) {
					fprintf(stderr, "error setting boolean "
					    "%s to value %d \n", name, val);
					errors++;
				}
		}
		fclose(boolf);
	}
	if (security_commit_booleans() < 0)
		return -1;

	if (errors)
		errno = EINVAL;
	return errors ? -1 : 0;
}
