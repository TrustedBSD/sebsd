/*-
 * Copyright (c) 2002, 2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_mac.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/mac.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/sysctl.h>

#include <sys/mac_policy.h>

#include <security/mac/mac_internal.h>

static int	mac_enforce_file = 1;
SYSCTL_INT(_security_mac, OID_AUTO, enforce_file, CTLFLAG_RW,
    &mac_enforce_file, 0, "Enforce MAC policy on file descriptors");
TUNABLE_INT("security.mac.enforce_file", &mac_enforce_file);

#ifdef MAC_DEBUG
static unsigned int nmacfiles;

SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, files, CTLFLAG_RD,
    &nmacfiles, 0, "number of files in use");
#endif

static struct label *
mac_file_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(M_WAITOK);
	MAC_PERFORM(init_file_label, label);
	MAC_DEBUG_COUNTER_INC(&nmacfiles);
	return (label);
}

void
mac_init_file(struct file *fp)
{

	fp->f_label = mac_file_label_alloc();
}

static void
mac_file_label_free(struct label *label)
{

	MAC_PERFORM(destroy_file_label, label);
	mac_labelzone_free(label);
	MAC_DEBUG_COUNTER_DEC(&nmacfiles);
}

void
mac_destroy_file(struct file *fp)
{

	mac_file_label_free(fp->f_label);
	fp->f_label = NULL;
}

int
mac_check_file_create(struct ucred *cred)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_create, cred);
	return (error);
}

int
mac_check_file_dup(struct ucred *cred, struct file *fp, int newfd)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_dup, cred, fp, fp->f_label, newfd);
	return (error);
}

int
mac_check_file_ioctl(struct ucred *cred, struct file *fp, u_long com)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_ioctl, cred, fp, fp->f_label, com);
	return (error);
}

int
mac_check_file_inherit(struct ucred *cred, struct file *fp)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_inherit, cred, fp, fp->f_label);
	return (error);
}

int
mac_check_file_receive(struct ucred *cred, struct file *fp)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_receive, cred, fp, fp->f_label);
	return (error);
}

int
mac_check_file_get_flags(struct ucred *cred, struct file *fp, u_int flags)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_get_flags, cred, fp, fp->f_label, flags);
	return (error);
}

int
mac_check_file_get_ofileflags(struct ucred *cred, struct file *fp, char flags)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_get_ofileflags, cred, fp, fp->f_label, flags);
	return (error);
}

int
mac_check_file_change_flags(struct ucred *cred, struct file *fp,
    u_int oldflags, u_int newflags)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_change_flags, cred, fp, fp->f_label, oldflags,
	    newflags);
	return (error);
}

int
mac_check_file_change_ofileflags(struct ucred *cred, struct file *fp,
    char oldflags, char newflags)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_change_ofileflags, cred, fp, fp->f_label,
	    oldflags, newflags);
	return (error);
}

int
mac_check_file_get_offset(struct ucred *cred, struct file *fp)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_get_offset, cred, fp, fp->f_label);
	return (error);
}

int
mac_check_file_change_offset(struct ucred *cred, struct file *fp)
{
	int error;

	if (!mac_enforce_file)
		return (0);
	MAC_CHECK(check_file_change_offset, cred, fp, fp->f_label);
	return (error);
}

void
mac_create_file(struct ucred *cred, struct file *fp)
{

	MAC_PERFORM(create_file, cred, fp, fp->f_label);
}
