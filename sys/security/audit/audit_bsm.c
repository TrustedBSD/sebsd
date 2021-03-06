/*
 * Copyright (c) 1999-2005 Apple Computer, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/security/audit/audit_bsm.c,v 1.4 2006/03/19 17:34:00 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/ipc.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/user.h>
#include <sys/systm.h>

#include <bsm/audit.h>
#include <bsm/audit_internal.h>
#include <bsm/audit_record.h>
#include <bsm/audit_kevents.h>

#include <security/audit/audit.h>
#include <security/audit/audit_private.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

MALLOC_DEFINE(M_AUDITBSM, "audit_bsm", "Audit BSM data");

/*
 * Forward declares.
 */
static void	audit_sys_auditon(struct audit_record *ar,
		    struct au_record *rec);

/*
 * Initialize the BSM auditing subsystem.
 */
void
kau_init(void)
{

	printf("BSM auditing present\n");
	au_evclassmap_init();
}

/*
 * This call reserves memory for the audit record.  Memory must be guaranteed
 * before any auditable event can be generated.  The au_record structure
 * maintains a reference to the memory allocated above and also the list of
 * tokens associated with this record
 */
static struct au_record *
kau_open(void)
{
	struct au_record *rec;

	rec = malloc(sizeof(*rec), M_AUDITBSM, M_WAITOK);
	rec->data = malloc(MAX_AUDIT_RECORD_SIZE * sizeof(u_char),
	    M_AUDITBSM, M_WAITOK | M_ZERO);
	TAILQ_INIT(&rec->token_q);
	rec->len = 0;
	rec->used = 1;

	return (rec);
}

/*
 * Store the token with the record descriptor.
 */
static void
kau_write(struct au_record *rec, struct au_token *tok)
{

	KASSERT(tok != NULL, ("kau_write: tok == NULL"));

	TAILQ_INSERT_TAIL(&rec->token_q, tok, tokens);
	rec->len += tok->len;
}

/*
 * Close out the audit record by adding the header token, identifying any
 * missing tokens.  Write out the tokens to the record memory.
 */
static void
kau_close(struct au_record *rec, struct timespec *ctime, short event)
{
	u_char *dptr;
	size_t tot_rec_size;
	token_t *cur, *hdr, *trail;
	struct timeval tm;

	tot_rec_size = rec->len + BSM_HEADER_SIZE + BSM_TRAILER_SIZE;
	if (tot_rec_size <= MAX_AUDIT_RECORD_SIZE) {
		/* Create the header token */
		tm.tv_usec = ctime->tv_nsec / 1000;
		tm.tv_sec = ctime->tv_sec;
		hdr = au_to_header32(tot_rec_size, event, 0, tm);
		TAILQ_INSERT_HEAD(&rec->token_q, hdr, tokens);

		trail = au_to_trailer(tot_rec_size);
		TAILQ_INSERT_TAIL(&rec->token_q, trail, tokens);

		/* Serialize token data to the record. */
		rec->len = tot_rec_size;
		dptr = rec->data;
		TAILQ_FOREACH(cur, &rec->token_q, tokens) {
			memcpy(dptr, cur->t_data, cur->len);
			dptr += cur->len;
		}
	}
}

/*
 * Free a BSM audit record by releasing all the tokens and clearing the audit
 * record information.
 */
void
kau_free(struct au_record *rec)
{
	struct au_token *tok;

	/* Free the token list. */
	while ((tok = TAILQ_FIRST(&rec->token_q))) {
		TAILQ_REMOVE(&rec->token_q, tok, tokens);
		free(tok->t_data, M_AUDITBSM);
		free(tok, M_AUDITBSM);
	}

	rec->used = 0;
	rec->len = 0;
	free(rec->data, M_AUDITBSM);
	free(rec, M_AUDITBSM);
}

/*
 * XXX May want turn some (or all) of these macros into functions in order
 * to reduce the generated code sized.
 *
 * XXXAUDIT: These macros assume that 'kar', 'ar', 'rec', and 'tok' in the
 * caller are OK with this.
 */
#define UPATH1_TOKENS do {						\
	if (ARG_IS_VALID(kar, ARG_UPATH1)) {				\
		tok = au_to_path(ar->ar_arg_upath1);			\
		kau_write(rec, tok);					\
	}								\
} while (0)

#define UPATH2_TOKENS do {						\
	if (ARG_IS_VALID(kar, ARG_UPATH2)) {				\
		tok = au_to_path(ar->ar_arg_upath2);			\
		kau_write(rec, tok);					\
	}								\
} while (0)

#define VNODE1_TOKENS do {						\
	if (ARG_IS_VALID(kar, ARG_VNODE1)) {  				\
		tok = au_to_attr32(&ar->ar_arg_vnode1);			\
		kau_write(rec, tok);					\
	}								\
} while (0)

#define UPATH1_VNODE1_TOKENS do {					\
	if (ARG_IS_VALID(kar, ARG_UPATH1)) {  				\
		UPATH1_TOKENS;						\
	}								\
	if (ARG_IS_VALID(kar, ARG_VNODE1)) {  				\
		tok = au_to_attr32(&ar->ar_arg_vnode1);			\
		kau_write(rec, tok);					\
	}								\
} while (0)

#define VNODE2_TOKENS do {						\
	if (ARG_IS_VALID(kar, ARG_VNODE2)) {  				\
		tok = au_to_attr32(&ar->ar_arg_vnode2);			\
		kau_write(rec, tok);					\
	}								\
} while (0)

#define FD_VNODE1_TOKENS	do {					\
	if (ARG_IS_VALID(kar, ARG_VNODE1)) {				\
		if (ARG_IS_VALID(kar, ARG_FD)) {			\
			tok = au_to_arg32(1, "fd", ar->ar_arg_fd);	\
			kau_write(rec, tok);				\
		}							\
		tok = au_to_attr32(&ar->ar_arg_vnode1);			\
		kau_write(rec, tok);					\
	} else {							\
		if (ARG_IS_VALID(kar, ARG_FD)) {			\
			tok = au_to_arg32(1, "non-file: fd",		\
			    ar->ar_arg_fd);				\
			kau_write(rec, tok);				\
		}							\
	}								\
} while (0)

#define PROCESS_PID_TOKENS(argn) do {					\
	if (ARG_IS_VALID(kar, ARG_PID)) {				\
		if ((ar->ar_arg_pid > 0) /* Kill a single process */	\
		    && (ARG_IS_VALID(kar, ARG_PROCESS))) {		\
			tok = au_to_process(ar->ar_arg_auid,		\
			    ar->ar_arg_euid, ar->ar_arg_egid,		\
			    ar->ar_arg_ruid, ar->ar_arg_rgid,		\
			    ar->ar_arg_pid, ar->ar_arg_asid,		\
			    &ar->ar_arg_termid);			\
			kau_write(rec, tok);				\
		} else {						\
			tok = au_to_arg32(argn, "process",		\
			    ar->ar_arg_pid);				\
			kau_write(rec, tok);				\
		}							\
	}								\
} while (0)								\

/*
 * Implement auditing for the auditon() system call. The audit tokens that
 * are generated depend on the command that was sent into the auditon()
 * system call.
 */
static void
audit_sys_auditon(struct audit_record *ar, struct au_record *rec)
{
	struct au_token *tok;

	switch (ar->ar_arg_cmd) {
	case A_SETPOLICY:
		if (sizeof(ar->ar_arg_auditon.au_flags) > 4)
			tok = au_to_arg64(1, "policy",
			    ar->ar_arg_auditon.au_flags);
		else
			tok = au_to_arg32(1, "policy",
			    ar->ar_arg_auditon.au_flags);
		kau_write(rec, tok);
		break;

	case A_SETKMASK:
		tok = au_to_arg32(2, "setkmask:as_success",
		    ar->ar_arg_auditon.au_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setkmask:as_failure",
		    ar->ar_arg_auditon.au_mask.am_failure);
		kau_write(rec, tok);
		break;

	case A_SETQCTRL:
		tok = au_to_arg32(3, "setqctrl:aq_hiwater",
		    ar->ar_arg_auditon.au_qctrl.aq_hiwater);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setqctrl:aq_lowater",
		    ar->ar_arg_auditon.au_qctrl.aq_lowater);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setqctrl:aq_bufsz",
		    ar->ar_arg_auditon.au_qctrl.aq_bufsz);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setqctrl:aq_delay",
		    ar->ar_arg_auditon.au_qctrl.aq_delay);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setqctrl:aq_minfree",
		    ar->ar_arg_auditon.au_qctrl.aq_minfree);
		kau_write(rec, tok);
		break;

	case A_SETUMASK:
		tok = au_to_arg32(3, "setumask:as_success",
		    ar->ar_arg_auditon.au_auinfo.ai_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setumask:as_failure",
		    ar->ar_arg_auditon.au_auinfo.ai_mask.am_failure);
		kau_write(rec, tok);
		break;

	case A_SETSMASK:
		tok = au_to_arg32(3, "setsmask:as_success",
		    ar->ar_arg_auditon.au_auinfo.ai_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setsmask:as_failure",
		    ar->ar_arg_auditon.au_auinfo.ai_mask.am_failure);
		kau_write(rec, tok);
		break;

	case A_SETCOND:
		if (sizeof(ar->ar_arg_auditon.au_cond) > 4)
			tok = au_to_arg64(3, "setcond",
			    ar->ar_arg_auditon.au_cond);
		else
			tok = au_to_arg32(3, "setcond",
			    ar->ar_arg_auditon.au_cond);
		kau_write(rec, tok);
		break;

	case A_SETCLASS:
		tok = au_to_arg32(2, "setclass:ec_event",
		    ar->ar_arg_auditon.au_evclass.ec_number);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setclass:ec_class",
		    ar->ar_arg_auditon.au_evclass.ec_class);
		kau_write(rec, tok);
		break;

	case A_SETPMASK:
		tok = au_to_arg32(2, "setpmask:as_success",
		    ar->ar_arg_auditon.au_aupinfo.ap_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setpmask:as_failure",
		    ar->ar_arg_auditon.au_aupinfo.ap_mask.am_failure);
		kau_write(rec, tok);
		break;

	case A_SETFSIZE:
		tok = au_to_arg32(2, "setfsize:filesize",
		    ar->ar_arg_auditon.au_fstat.af_filesz);
		kau_write(rec, tok);
		break;

	default:
		break;
	}
}

/*
 * Convert an internal kernel audit record to a BSM record and return a
 * success/failure indicator. The BSM record is passed as an out parameter to
 * this function.
 *
 * Return conditions:
 *   BSM_SUCCESS: The BSM record is valid
 *   BSM_FAILURE: Failure; the BSM record is NULL.
 *   BSM_NOAUDIT: The event is not auditable for BSM; the BSM record is NULL.
 */
int
kaudit_to_bsm(struct kaudit_record *kar, struct au_record **pau)
{
	struct au_token *tok, *subj_tok;
	struct au_record *rec;
	au_tid_t tid;
	struct audit_record *ar;
	int ctr;

	KASSERT(kar != NULL, ("kaudit_to_bsm: kar == NULL"));

	*pau = NULL;
	ar = &kar->k_ar;
	rec = kau_open();

	/* Create the subject token */
	tid.port = ar->ar_subj_term.port;
	tid.machine = ar->ar_subj_term.machine;
	subj_tok = au_to_subject32(ar->ar_subj_auid,  /* audit ID */
		ar->ar_subj_cred.cr_uid, /* eff uid */
		ar->ar_subj_egid,	/* eff group id */
		ar->ar_subj_ruid, 	/* real uid */
		ar->ar_subj_rgid, 	/* real group id */
		ar->ar_subj_pid,	/* process id */
		ar->ar_subj_asid,	/* session ID */
		&tid);

	/*
	 * The logic inside each case fills in the tokens required for the
	 * event, except for the header, trailer, and return tokens.  The
	 * header and trailer tokens are added by the kau_close() function.
	 * The return token is added outside of the switch statement.
	 */
	switch(ar->ar_event) {
	case AUE_ACCEPT:
	case AUE_BIND:
	case AUE_CONNECT:
	case AUE_RECVFROM:
	case AUE_RECVMSG:
	case AUE_SENDMSG:
	case AUE_SENDTO:
		/*
		 * Socket-related events.
		 */
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SADDRINET)) {
			tok = au_to_sock_inet((struct sockaddr_in *)
			    &ar->ar_arg_sockaddr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SADDRUNIX)) {
			tok = au_to_sock_unix((struct sockaddr_un *)
			    &ar->ar_arg_sockaddr);
			kau_write(rec, tok);
			UPATH1_TOKENS;
		}
		/* XXX Need to handle ARG_SADDRINET6 */
		break;

	case AUE_SOCKET:
	case AUE_SOCKETPAIR:
		if (ARG_IS_VALID(kar, ARG_SOCKINFO)) {
			tok = au_to_arg32(1,"domain",
			    ar->ar_arg_sockinfo.so_domain);
			kau_write(rec, tok);
			tok = au_to_arg32(2,"type",
			    ar->ar_arg_sockinfo.so_type);
			kau_write(rec, tok);
			tok = au_to_arg32(3,"protocol",
			    ar->ar_arg_sockinfo.so_protocol);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETSOCKOPT:
	case AUE_SHUTDOWN:
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		break;

	case AUE_ACCT:
		if (ARG_IS_VALID(kar, ARG_UPATH1)) {
			UPATH1_VNODE1_TOKENS;
		} else {
			tok = au_to_arg32(1, "accounting off", 0);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETAUID:
		if (ARG_IS_VALID(kar, ARG_AUID)) {
			tok = au_to_arg32(2, "setauid", ar->ar_arg_auid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETAUDIT:
		if (ARG_IS_VALID(kar, ARG_AUID)) {
			tok = au_to_arg32(1, "setaudit:auid",
			    ar->ar_arg_auid);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:port",
			    ar->ar_arg_termid.port);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:machine",
			    ar->ar_arg_termid.machine);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:as_success",
			    ar->ar_arg_amask.am_success);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:as_failure",
			    ar->ar_arg_amask.am_failure);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:asid",
			    ar->ar_arg_asid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETAUDIT_ADDR:
		break;		/* XXX need to add arguments */

	case AUE_AUDITON:
		/*
		 * For AUDITON commands without own event, audit the cmd.
		 */
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(1, "cmd", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		/* fall thru */

	case AUE_AUDITON_GETCAR:
	case AUE_AUDITON_GETCLASS:
	case AUE_AUDITON_GETCOND:
	case AUE_AUDITON_GETCWD:
	case AUE_AUDITON_GETKMASK:
	case AUE_AUDITON_GETSTAT:
	case AUE_AUDITON_GPOLICY:
	case AUE_AUDITON_GQCTRL:
	case AUE_AUDITON_SETCLASS:
	case AUE_AUDITON_SETCOND:
	case AUE_AUDITON_SETKMASK:
	case AUE_AUDITON_SETSMASK:
	case AUE_AUDITON_SETSTAT:
	case AUE_AUDITON_SETUMASK:
	case AUE_AUDITON_SPOLICY:
	case AUE_AUDITON_SQCTRL:
		if (ARG_IS_VALID(kar, ARG_AUDITON))
			audit_sys_auditon(ar, rec);
		break;

	case AUE_AUDITCTL:
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_EXIT:
		if (ARG_IS_VALID(kar, ARG_EXIT)) {
			tok = au_to_exit(ar->ar_arg_exitretval,
			    ar->ar_arg_exitstatus);
			kau_write(rec, tok);
		}
		break;

	case AUE_ADJTIME:
	case AUE_AUDIT:
	case AUE_GETAUDIT:
	case AUE_GETAUDIT_ADDR:
	case AUE_GETAUID:
	case AUE_GETFSSTAT:
	case AUE_PIPE:
	case AUE_SETPGRP:
	case AUE_SETRLIMIT:
	case AUE_SETSID:
	case AUE_SETTIMEOFDAY:
	case AUE_NEWSYSTEMSHREG:
		/*
		 * Header, subject, and return tokens added at end.
		 */
		break;

	case AUE_ACCESS:
	case AUE_CHDIR:
	case AUE_CHROOT:
	case AUE_EACCESS:
	case AUE_EXECVE:
	case AUE_GETATTRLIST:
	case AUE_NFS_GETFH:
	case AUE_LSTAT:
	case AUE_MKFIFO:
	case AUE_PATHCONF:
	case AUE_READLINK:
	case AUE_REVOKE:
	case AUE_RMDIR:
	case AUE_SEARCHFS:
	case AUE_SETATTRLIST:
	case AUE_STAT:
	case AUE_STATFS:
	case AUE_TRUNCATE:
	case AUE_UNDELETE:
	case AUE_UNLINK:
	case AUE_UTIMES:
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_CHFLAGS:
	case AUE_LCHFLAGS:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_CHMOD:
	case AUE_LCHMOD:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "new file mode",
			    ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_CHOWN:
	case AUE_LCHOWN:
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(2, "new file uid", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_GID)) {
			tok = au_to_arg32(3, "new file gid", ar->ar_arg_gid);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_EXCHANGEDATA:
		UPATH1_VNODE1_TOKENS;
		UPATH2_TOKENS;
		break;

	case AUE_CLOSE:
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(2, "fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_FCHMOD:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "new file mode",
			    ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_FCHDIR:
	case AUE_FPATHCONF:
	case AUE_FSTAT:		/* XXX Need to handle sockets and shm */
	case AUE_FSTATFS:
	case AUE_FSYNC:
	case AUE_FTRUNCATE:
	case AUE_FUTIMES:
	case AUE_GETDIRENTRIES:
	case AUE_GETDIRENTRIESATTR:
		FD_VNODE1_TOKENS;
		break;

	case AUE_FCHOWN:
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(2, "new file uid", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_GID)) {
			tok = au_to_arg32(3, "new file gid", ar->ar_arg_gid);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_FCNTL:
		if (ar->ar_arg_cmd == F_GETLK || ar->ar_arg_cmd == F_SETLK ||
			ar->ar_arg_cmd == F_SETLKW) {
			if (ARG_IS_VALID(kar, ARG_CMD)) {
				tok = au_to_arg32(2, "cmd", ar->ar_arg_cmd);
				kau_write(rec, tok);
			}
			FD_VNODE1_TOKENS;
		}
		break;

	case AUE_FCHFLAGS:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_FLOCK:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "operation", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_RFORK:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(1, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		/* fall through */
	case AUE_FORK:
	case AUE_VFORK:
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(0, "child PID", ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		break;

	case AUE_IOCTL:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "cmd", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_ADDR)) {
			tok = au_to_arg32(1, "arg",
			    (u_int32_t)(uintptr_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VNODE1))
			FD_VNODE1_TOKENS;
		else {
			if (ARG_IS_VALID(kar, ARG_SOCKINFO)) {
				tok = kau_to_socket(&ar->ar_arg_sockinfo);
				kau_write(rec, tok);
			} else {
				if (ARG_IS_VALID(kar, ARG_FD)) {
					tok = au_to_arg32(1, "fd",
					    ar->ar_arg_fd);
			    		kau_write(rec, tok);
				}
			}
		}
		break;

	case AUE_KILL:
		if (ARG_IS_VALID(kar, ARG_SIGNUM)) {
			tok = au_to_arg32(2, "signal", ar->ar_arg_signum);
			kau_write(rec, tok);
		}
		PROCESS_PID_TOKENS(1);
		break;

	case AUE_KTRACE:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "ops", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE)) {
			tok = au_to_arg32(3, "trpoints", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		PROCESS_PID_TOKENS(4);
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_LINK:
	case AUE_RENAME:
		UPATH1_VNODE1_TOKENS;
		UPATH2_TOKENS;
		break;

	case AUE_LOADSHFILE:
		if (ARG_IS_VALID(kar, ARG_ADDR)) {
			tok = au_to_arg32(4, "base addr",
			    (u_int32_t)(uintptr_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_MKDIR:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_MKNOD:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_DEV)) {
			tok = au_to_arg32(3, "dev", ar->ar_arg_dev);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_MMAP:
	case AUE_MUNMAP:
	case AUE_MPROTECT:
	case AUE_MLOCK:
	case AUE_MUNLOCK:
	case AUE_MINHERIT:
		if (ARG_IS_VALID(kar, ARG_ADDR)) {
			tok = au_to_arg32(1, "addr",
			    (u_int32_t)(uintptr_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_LEN)) {
			tok = au_to_arg32(2, "len", ar->ar_arg_len);
			kau_write(rec, tok);
		}
		if (ar->ar_event == AUE_MMAP)
			FD_VNODE1_TOKENS;
		if (ar->ar_event == AUE_MPROTECT) {
			if (ARG_IS_VALID(kar, ARG_VALUE)) {
				tok = au_to_arg32(3, "protection",
				    ar->ar_arg_value);
				kau_write(rec, tok);
			}
		}
		if (ar->ar_event == AUE_MINHERIT) {
			if (ARG_IS_VALID(kar, ARG_VALUE)) {
				tok = au_to_arg32(3, "inherit",
				    ar->ar_arg_value);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_MOUNT:
		/* XXX Need to handle NFS mounts */
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(3, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		/* fall through */

	case AUE_UMOUNT:
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_MSGCTL:
		ar->ar_event = msgctl_to_event(ar->ar_arg_svipc_cmd);
		/* Fall through */

	case AUE_MSGRCV:
	case AUE_MSGSND:
		tok = au_to_arg32(1, "msg ID", ar->ar_arg_svipc_id);
		kau_write(rec, tok);
		if (ar->ar_errno != EINVAL) {
			tok = au_to_ipc(AT_IPC_MSG, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		break;

	case AUE_MSGGET:
		if (ar->ar_errno == 0) {
			if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
				tok = au_to_ipc(AT_IPC_MSG,
				    ar->ar_arg_svipc_id);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_RESETSHFILE:
		if (ARG_IS_VALID(kar, ARG_ADDR)) {
			tok = au_to_arg32(1, "base addr",
			    (u_int32_t)(uintptr_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		break;

	case AUE_OPEN_RC:
	case AUE_OPEN_RTC:
	case AUE_OPEN_RWC:
	case AUE_OPEN_RWTC:
	case AUE_OPEN_WC:
	case AUE_OPEN_WTC:
	/* case AUE_O_CREAT: */		/* AUE_O_CREAT == AUE_OPEN_RWTC */
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		/* fall through */

	case AUE_OPEN_R:
	case AUE_OPEN_RT:
	case AUE_OPEN_RW:
	case AUE_OPEN_RWT:
	case AUE_OPEN_W:
	case AUE_OPEN_WT:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_PTRACE:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(1, "request", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_ADDR)) {
			tok = au_to_arg32(3, "addr",
			    (u_int32_t)(uintptr_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE)) {
			tok = au_to_arg32(4, "data", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		PROCESS_PID_TOKENS(2);
		break;

	case AUE_QUOTACTL:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "command", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(3, "uid", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_REBOOT:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(1, "howto", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		break;

	case AUE_SEMCTL:
		ar->ar_event = semctl_to_event(ar->ar_arg_svipc_cmd);
		/* Fall through */

	case AUE_SEMOP:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
			tok = au_to_arg32(1, "sem ID", ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			if (ar->ar_errno != EINVAL) {
				tok = au_to_ipc(AT_IPC_SEM,
				    ar->ar_arg_svipc_id);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_SEMGET:
		if (ar->ar_errno == 0) {
			if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
				tok = au_to_ipc(AT_IPC_SEM,
				    ar->ar_arg_svipc_id);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_SETEGID:
		if (ARG_IS_VALID(kar, ARG_EGID)) {
			tok = au_to_arg32(1, "gid", ar->ar_arg_egid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETEUID:
		if (ARG_IS_VALID(kar, ARG_EUID)) {
			tok = au_to_arg32(1, "uid", ar->ar_arg_euid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETREGID:
		if (ARG_IS_VALID(kar, ARG_RGID)) {
			tok = au_to_arg32(1, "rgid", ar->ar_arg_rgid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_EGID)) {
			tok = au_to_arg32(2, "egid", ar->ar_arg_egid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETREUID:
		if (ARG_IS_VALID(kar, ARG_RUID)) {
			tok = au_to_arg32(1, "ruid", ar->ar_arg_ruid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_EUID)) {
			tok = au_to_arg32(2, "euid", ar->ar_arg_euid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETRESGID:
		if (ARG_IS_VALID(kar, ARG_RGID)) {
			tok = au_to_arg32(1, "rgid", ar->ar_arg_rgid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_EGID)) {
			tok = au_to_arg32(2, "egid", ar->ar_arg_egid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SGID)) {
			tok = au_to_arg32(3, "sgid", ar->ar_arg_sgid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETRESUID:
		if (ARG_IS_VALID(kar, ARG_RUID)) {
			tok = au_to_arg32(1, "ruid", ar->ar_arg_ruid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_EUID)) {
			tok = au_to_arg32(2, "euid", ar->ar_arg_euid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SUID)) {
			tok = au_to_arg32(3, "suid", ar->ar_arg_suid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETGID:
		if (ARG_IS_VALID(kar, ARG_GID)) {
			tok = au_to_arg32(1, "gid", ar->ar_arg_gid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETUID:
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(1, "uid", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETGROUPS:
		if (ARG_IS_VALID(kar, ARG_GROUPSET)) {
			for(ctr = 0; ctr < ar->ar_arg_groups.gidset_size; ctr++)
			{
				tok = au_to_arg32(1, "setgroups", 							ar->ar_arg_groups.gidset[ctr]);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_SETLOGIN:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETPRIORITY:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(1, "which", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(2, "who", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE)) {
			tok = au_to_arg32(2, "priority", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETPRIVEXEC:
		if (ARG_IS_VALID(kar, ARG_VALUE)) {
			tok = au_to_arg32(1, "flag", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		break;

	/* AUE_SHMAT, AUE_SHMCTL, AUE_SHMDT and AUE_SHMGET are SysV IPC */
	case AUE_SHMAT:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
			tok = au_to_arg32(1, "shmid", ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			/* XXXAUDIT: Does having the ipc token make sense? */
			tok = au_to_ipc(AT_IPC_SHM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SVIPC_ADDR)) {
			tok = au_to_arg32(2, "shmaddr",
			    (int)(uintptr_t)ar->ar_arg_svipc_addr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SVIPC_PERM)) {
			tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
			kau_write(rec, tok);
		}
		break;

	case AUE_SHMCTL:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
			tok = au_to_arg32(1, "shmid", ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			/* XXXAUDIT: Does having the ipc token make sense? */
			tok = au_to_ipc(AT_IPC_SHM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		switch (ar->ar_arg_svipc_cmd) {
		case IPC_STAT:
			ar->ar_event = AUE_SHMCTL_STAT;
			break;
		case IPC_RMID:
			ar->ar_event = AUE_SHMCTL_RMID;
			break;
		case IPC_SET:
			ar->ar_event = AUE_SHMCTL_SET;
			if (ARG_IS_VALID(kar, ARG_SVIPC_PERM)) {
				tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
				kau_write(rec, tok);
			}
			break;
		default:
			break;	/* We will audit a bad command */
		}
		break;

	case AUE_SHMDT:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ADDR)) {
			tok = au_to_arg32(1, "shmaddr",
			    (int)(uintptr_t)ar->ar_arg_svipc_addr);
			kau_write(rec, tok);
		}
		break;

	case AUE_SHMGET:
		/* This is unusual; the return value is in an argument token */
		if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
			tok = au_to_arg32(0, "shmid", ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			tok = au_to_ipc(AT_IPC_SHM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SVIPC_PERM)) {
			tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
			kau_write(rec, tok);
		}
		break;

	/* AUE_SHMOPEN, AUE_SHMUNLINK, AUE_SEMOPEN, AUE_SEMCLOSE
	 * and AUE_SEMUNLINK are Posix IPC */
	case AUE_SHMOPEN:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ADDR)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
	case AUE_SHMUNLINK:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_POSIX_IPC_PERM)) {
		/* Create an ipc_perm token */
			struct ipc_perm perm;
			perm.uid = ar->ar_arg_pipc_perm.pipc_uid;
			perm.gid = ar->ar_arg_pipc_perm.pipc_gid;
			perm.cuid = ar->ar_arg_pipc_perm.pipc_uid;
			perm.cgid = ar->ar_arg_pipc_perm.pipc_gid;
			perm.mode = ar->ar_arg_pipc_perm.pipc_mode;
			perm.seq = 0;
			perm.key = 0;
			tok = au_to_ipc_perm(&perm);
			kau_write(rec, tok);
		}
		break;

	case AUE_SEMOPEN:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE)) {
			tok = au_to_arg32(4, "value", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		/* fall through */

	case AUE_SEMUNLINK:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_POSIX_IPC_PERM)) {
		/* Create an ipc_perm token */
			struct ipc_perm perm;
			perm.uid = ar->ar_arg_pipc_perm.pipc_uid;
			perm.gid = ar->ar_arg_pipc_perm.pipc_gid;
			perm.cuid = ar->ar_arg_pipc_perm.pipc_uid;
			perm.cgid = ar->ar_arg_pipc_perm.pipc_gid;
			perm.mode = ar->ar_arg_pipc_perm.pipc_mode;
			perm.seq = 0;
			perm.key = 0;
			tok = au_to_ipc_perm(&perm);
			kau_write(rec, tok);
		}
		break;

	case AUE_SEMCLOSE:
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "sem", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		break;

	case AUE_SYMLINK:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_SYSCTL:
		if (ARG_IS_VALID(kar, ARG_CTLNAME | ARG_LEN)) {
			for (ctr = 0; ctr < ar->ar_arg_len; ctr++) {
				tok = au_to_arg32(1, "name",
				    ar->ar_arg_ctlname[ctr]);
				kau_write(rec, tok);
			}
		}
		if (ARG_IS_VALID(kar, ARG_VALUE)) {
			tok = au_to_arg32(5, "newval", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;

	case AUE_UMASK:
		if (ARG_IS_VALID(kar, ARG_MASK)) {
			tok = au_to_arg32(1, "new mask", ar->ar_arg_mask);
			kau_write(rec, tok);
		}
		tok = au_to_arg32(0, "prev mask", ar->ar_retval);
		kau_write(rec, tok);
		break;

	case AUE_WAIT4:
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(0, "pid", ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		break;

	default:
		printf("BSM conversion requested for unknown event %d\n",
		    ar->ar_event);
		/* Write the subject token so it is properly freed here. */
		kau_write(rec, subj_tok);
		kau_free(rec);
		return (BSM_NOAUDIT);
	}

	kau_write(rec, subj_tok);
	tok = au_to_return32((char)ar->ar_errno, ar->ar_retval);
	kau_write(rec, tok);  /* Every record gets a return token */

	kau_close(rec, &ar->ar_endtime, ar->ar_event);

	*pau = rec;
	return (BSM_SUCCESS);
}

/*
 * Verify that a record is a valid BSM record. This verification is simple
 * now, but may be expanded on sometime in the future.  Return 1 if the
 * record is good, 0 otherwise.
 */
int
bsm_rec_verify(void *rec)
{
	char c = *(char *)rec;

	/*
	 * Check the token ID of the first token; it has to be a header
	 * token.
	 *
	 * XXXAUDIT There needs to be a token structure to map a token.
	 * XXXAUDIT 'Shouldn't be simply looking at the first char.
	 */
	if ((c != AUT_HEADER32) && (c != AUT_HEADER32_EX) &&
	    (c != AUT_HEADER64) && (c != AUT_HEADER64_EX))
		return (0);
	return (1);
}
