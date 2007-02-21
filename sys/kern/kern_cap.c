/*-
 * Copyright (c) 2001, 2003, 2004 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by McAfee
 * Research, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
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

#include "opt_mac.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/capability.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/mac.h>

const char *
capv_to_text(cap_value_t capv)
{

	switch (capv) {
	case CAP_CHOWN:
		return ("CAP_CHOWN");
	case CAP_DAC_EXECUTE:
		return ("CAP_DAC_EXECUTE");
	case CAP_DAC_WRITE:
		return ("CAP_DAC_WRITE");
	case CAP_DAC_READ_SEARCH:
		return ("CAP_DAC_READ_SEARCH");
	case CAP_FOWNER:
		return ("CAP_FOWNER");
	case CAP_FSETID:
		return ("CAP_FSETID");
	case CAP_KILL:
		return ("CAP_KILL");
	case CAP_SETFCAP:
		return ("CAP_SETFCAP");
	case CAP_SETGID:
		return ("CAP_SETGID");
	case CAP_SETUID:
		return ("CAP_SETUID");
	case CAP_AUDIT_CONTROL:
		return ("CAP_AUDIT_CONTROL");
	case CAP_AUDIT_WRITE:
		return ("CAP_AUDIT_WRITE");
	case CAP_SYS_SETFFLAG:
		return ("CAP_SYS_SETFFLAG");
	case CAP_NET_BIND_SERVICE:
		return ("CAP_NET_BIND_SERVICE");
	case CAP_NET_BROADCAST:
		return ("CAP_NET_BROADCAST");
	case CAP_NET_ADMIN:
		return ("CAP_NET_ADMIN");
	case CAP_NET_RAW:
		return ("CAP_NET_RAW");
	case CAP_IPC_LOCK:
		return ("CAP_IPC_LOCK");
	case CAP_IPC_OWNER:
		return ("CAP_IPC_OWNER");
	case CAP_SYS_MODULE:
		return ("CAP_SYS_MODULE");
	case CAP_SYS_RAWIO:
		return ("CAP_SYS_RAWIO");
	case CAP_SYS_CHROOT:
		return ("CAP_SYS_CHROOT");
	case CAP_SYS_PTRACE:
		return ("CAP_SYS_PTRACE");
	case CAP_SYS_PACCT:
		return ("CAP_SYS_PACCT");
	case CAP_SYS_ADMIN:
		return ("CAP_SYS_ADMIN");
	case CAP_SYS_BOOT:
		return ("CAP_SYS_BOOT");
	case CAP_SYS_NICE:
		return ("CAP_SYS_NICE");
	case CAP_SYS_RESOURCE:
		return ("CAP_SYS_RESOURCE");
	case CAP_SYS_TIME:
		return ("CAP_SYS_TIME");
	case CAP_SYS_TTY_CONFIG:
		return ("CAP_SYS_TTY_CONFIG");
	case CAP_MKNOD:
		return ("CAP_MKNOD");
	default:
		return ("UNKNOWN!");
	}
}

int
cap_check_cred(struct ucred *cred, cap_value_t cap, int jailflags)
{
	int error;

#ifdef MAC
	error = mac_check_cap(cred, cap);
	if (error)
		return error;
#endif

	error = suser_cred(cred, jailflags);

	return (error);
}

int
cap_check(struct thread *td, cap_value_t cap)
{

	return (cap_check_cred(td->td_ucred, cap, 0));
}
