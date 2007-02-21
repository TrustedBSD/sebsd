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
 * $FreeBSD: src/sys/security/audit/audit_syscalls.c,v 1.3 2006/03/19 17:34:00 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <bsm/audit.h>
#include <bsm/audit_kevents.h>
#include <security/audit/audit.h>
#include <security/audit/audit_private.h>

#ifdef AUDIT

/*
 * MPSAFE
 *
 * System call to allow a user space application to submit a BSM audit record
 * to the kernel for inclusion in the audit log. This function does little
 * verification on the audit record that is submitted.
 *
 * XXXAUDIT: Audit preselection for user records does not currently work,
 * since we pre-select only based on the AUE_audit event type, not the event
 * type submitted as part of the user audit data.
 */
/* ARGSUSED */
int
audit(struct thread *td, struct audit_args *uap)
{
	int error;
	void * rec;
	struct kaudit_record *ar;

	error = suser(td);
	if (error)
		return (error);

	if ((uap->length <= 0) || (uap->length > audit_qctrl.aq_bufsz))
		return (EINVAL);

	ar = currecord();

	/*
	 * If there's no current audit record (audit() itself not audited)
	 * commit the user audit record.
	 */
	if (ar == NULL) {

		/*
		 * This is not very efficient; we're required to allocate a
		 * complete kernel audit record just so the user record can
		 * tag along.
		 *
		 * XXXAUDIT: Maybe AUE_AUDIT in the system call context and
		 * special pre-select handling?
		 */
		td->td_ar = audit_new(AUE_NULL, td);
		if (td->td_ar == NULL)
			return (ENOTSUP);
		ar = td->td_ar;
	}

	if (uap->length > MAX_AUDIT_RECORD_SIZE)
		return (EINVAL);

	rec = malloc(uap->length, M_AUDITDATA, M_WAITOK);

	error = copyin(uap->record, rec, uap->length);
	if (error)
		goto free_out;

	/* Verify the record. */
	if (bsm_rec_verify(rec) == 0) {
		error = EINVAL;
		goto free_out;
	}

	/*
	 * Attach the user audit record to the kernel audit record. Because
	 * this system call is an auditable event, we will write the user
	 * record along with the record for this audit event.
	 *
	 * XXXAUDIT: KASSERT appropriate starting values of k_udata, k_ulen,
	 * k_ar_commit & AR_COMMIT_USER?
	 */
	ar->k_udata = rec;
	ar->k_ulen  = uap->length;
	ar->k_ar_commit |= AR_COMMIT_USER;
	return (0);

free_out:
	/*
	 * audit_syscall_exit() will free the audit record on the thread even
	 * if we allocated it above.
	 */
	free(rec, M_AUDITDATA);
	return (error);
}

/*
 * MPSAFE
 *
 *  System call to manipulate auditing.
 */
/* ARGSUSED */
int
auditon(struct thread *td, struct auditon_args *uap)
{
	int error;
	union auditon_udata udata;
	struct proc *tp;

	AUDIT_ARG(cmd, uap->cmd);
	error = suser(td);
	if (error)
		return (error);

	if ((uap->length <= 0) || (uap->length > sizeof(union auditon_udata)))
		return (EINVAL);

	memset((void *)&udata, 0, sizeof(udata));

	/*
	 * Some of the GET commands use the arguments too.
	 */
	switch (uap->cmd) {
	case A_SETPOLICY:
	case A_SETKMASK:
	case A_SETQCTRL:
	case A_SETSTAT:
	case A_SETUMASK:
	case A_SETSMASK:
	case A_SETCOND:
	case A_SETCLASS:
	case A_SETPMASK:
	case A_SETFSIZE:
	case A_SETKAUDIT:
	case A_GETCLASS:
	case A_GETPINFO:
	case A_GETPINFO_ADDR:
	case A_SENDTRIGGER:
		error = copyin(uap->data, (void *)&udata, uap->length);
		if (error)
			return (error);
		AUDIT_ARG(auditon, &udata);
		break;
	}

	/*
	 * XXX Need to implement these commands by accessing the global
	 * values associated with the commands.
	 *
	 * XXXAUDIT: Locking?
	 */
	switch (uap->cmd) {
	case A_GETPOLICY:
		if (!audit_fail_stop)
			udata.au_policy |= AUDIT_CNT;
		if (audit_panic_on_write_fail)
			udata.au_policy |= AUDIT_AHLT;
		break;

	case A_SETPOLICY:
		if (udata.au_policy & ~(AUDIT_CNT|AUDIT_AHLT))
			return (EINVAL);
		/*
		 * XXX - Need to wake up waiters if the policy relaxes?
		 */
		audit_fail_stop = ((udata.au_policy & AUDIT_CNT) == 0);
		audit_panic_on_write_fail = (udata.au_policy & AUDIT_AHLT);
		break;

	case A_GETKMASK:
		udata.au_mask = audit_nae_mask;
		break;

	case A_SETKMASK:
		audit_nae_mask = udata.au_mask;
		break;

	case A_GETQCTRL:
		udata.au_qctrl = audit_qctrl;
		break;

	case A_SETQCTRL:
		if ((udata.au_qctrl.aq_hiwater > AQ_MAXHIGH) ||
		    (udata.au_qctrl.aq_lowater >= udata.au_qctrl.aq_hiwater) ||
		    (udata.au_qctrl.aq_bufsz > AQ_MAXBUFSZ) ||
		    (udata.au_qctrl.aq_minfree < 0) ||
		    (udata.au_qctrl.aq_minfree > 100))
			return (EINVAL);

		audit_qctrl = udata.au_qctrl;
		/* XXX The queue delay value isn't used with the kernel. */
		audit_qctrl.aq_delay = -1;
		break;

	case A_GETCWD:
		return (ENOSYS);
		break;

	case A_GETCAR:
		return (ENOSYS);
		break;

	case A_GETSTAT:
		return (ENOSYS);
		break;

	case A_SETSTAT:
		return (ENOSYS);
		break;

	case A_SETUMASK:
		return (ENOSYS);
		break;

	case A_SETSMASK:
		return (ENOSYS);
		break;

	case A_GETCOND:
		if (audit_enabled && !audit_suspended)
			udata.au_cond = AUC_AUDITING;
		else
			udata.au_cond = AUC_NOAUDIT;
		break;

	case A_SETCOND:
		if (udata.au_cond == AUC_NOAUDIT)
			audit_suspended = 1;
		if (udata.au_cond == AUC_AUDITING)
			audit_suspended = 0;
		if (udata.au_cond == AUC_DISABLED) {
			audit_suspended = 1;
			audit_shutdown(NULL, 0);
		}
		break;

	case A_GETCLASS:
		udata.au_evclass.ec_class = au_event_class(
		    udata.au_evclass.ec_number);
		break;

	case A_SETCLASS:
		au_evclassmap_insert(udata.au_evclass.ec_number,
		    udata.au_evclass.ec_class);
		break;

	case A_GETPINFO:
		if (udata.au_aupinfo.ap_pid < 1)
			return (EINVAL);

		/* XXXAUDIT: p_cansee()? */
		if ((tp = pfind(udata.au_aupinfo.ap_pid)) == NULL)
			return (EINVAL);

		udata.au_aupinfo.ap_auid = tp->p_au->ai_auid;
		udata.au_aupinfo.ap_mask.am_success =
		    tp->p_au->ai_mask.am_success;
		udata.au_aupinfo.ap_mask.am_failure =
		    tp->p_au->ai_mask.am_failure;
		udata.au_aupinfo.ap_termid.machine =
		    tp->p_au->ai_termid.machine;
		udata.au_aupinfo.ap_termid.port = tp->p_au->ai_termid.port;
		udata.au_aupinfo.ap_asid = tp->p_au->ai_asid;
		PROC_UNLOCK(tp);
		break;

	case A_SETPMASK:
		if (udata.au_aupinfo.ap_pid < 1)
			return (EINVAL);

		/* XXXAUDIT: p_cansee()? */
		if ((tp = pfind(udata.au_aupinfo.ap_pid)) == NULL)
			return (EINVAL);

		tp->p_au->ai_mask.am_success =
		    udata.au_aupinfo.ap_mask.am_success;
		tp->p_au->ai_mask.am_failure =
		    udata.au_aupinfo.ap_mask.am_failure;
		PROC_UNLOCK(tp);
		break;

	case A_SETFSIZE:
		if ((udata.au_fstat.af_filesz != 0) &&
		   (udata.au_fstat.af_filesz < MIN_AUDIT_FILE_SIZE))
			return (EINVAL);
		audit_fstat.af_filesz = udata.au_fstat.af_filesz;
		break;

	case A_GETFSIZE:
		udata.au_fstat.af_filesz = audit_fstat.af_filesz;
		udata.au_fstat.af_currsz = audit_fstat.af_currsz;
		break;

	case A_GETPINFO_ADDR:
		return (ENOSYS);
		break;

	case A_GETKAUDIT:
		return (ENOSYS);
		break;

	case A_SETKAUDIT:
		return (ENOSYS);
		break;

	case A_SENDTRIGGER:
		if ((udata.au_trigger < AUDIT_TRIGGER_MIN) ||
		    (udata.au_trigger > AUDIT_TRIGGER_MAX))
			return (EINVAL);
		return (send_trigger(udata.au_trigger));
	}

	/*
	 * Copy data back to userspace for the GET comands.
	 */
	switch (uap->cmd) {
	case A_GETPOLICY:
	case A_GETKMASK:
	case A_GETQCTRL:
	case A_GETCWD:
	case A_GETCAR:
	case A_GETSTAT:
	case A_GETCOND:
	case A_GETCLASS:
	case A_GETPINFO:
	case A_GETFSIZE:
	case A_GETPINFO_ADDR:
	case A_GETKAUDIT:
		error = copyout((void *)&udata, uap->data, uap->length);
		if (error)
			return (error);
		break;
	}

	return (0);
}

/*
 * MPSAFE
 *
 * System calls to manage the user audit information.
 */
/* ARGSUSED */
int
getauid(struct thread *td, struct getauid_args *uap)
{
	int error;
	au_id_t id;

	error = suser(td);
	if (error)
		return (error);

	/*
	 * XXX: Integer read on static pointer dereference: doesn't need
	 * locking?
	 */
	PROC_LOCK(td->td_proc);
	id = td->td_proc->p_au->ai_auid;
	PROC_UNLOCK(td->td_proc);
	return copyout(&id, uap->auid, sizeof(id));
}

/* MPSAFE */
/* ARGSUSED */
int
setauid(struct thread *td, struct setauid_args *uap)
{
	int error;
	au_id_t id;

	error = suser(td);
	if (error)
		return (error);

	error = copyin(uap->auid, &id, sizeof(id));
	if (error)
		return (error);

	audit_arg_auid(id);

	/*
	 * XXX: Integer write on static pointer dereference: doesn't need
	 * locking?
	 *
	 * XXXAUDIT: Might need locking to serialize audit events in the same
	 * order as change events?  Or maybe that's an under-solveable
	 * problem.
	 *
	 * XXXRW: Test privilege while holding the proc lock?
	 */
	PROC_LOCK(td->td_proc);
	td->td_proc->p_au->ai_auid = id;
	PROC_UNLOCK(td->td_proc);

	return (0);
}

/*
 * MPSAFE
 * System calls to get and set process audit information.
 */
/* ARGSUSED */
int
getaudit(struct thread *td, struct getaudit_args *uap)
{
	struct auditinfo ai;
	int error;

	error = suser(td);
	if (error)
		return (error);

	PROC_LOCK(td->td_proc);
	ai = *td->td_proc->p_au;
	PROC_UNLOCK(td->td_proc);

	return (copyout(&ai, uap->auditinfo, sizeof(ai)));
}

/* MPSAFE */
/* ARGSUSED */
int
setaudit(struct thread *td, struct setaudit_args *uap)
{
	struct auditinfo ai;
	int error;

	error = suser(td);
	if (error)
		return (error);

	error = copyin(uap->auditinfo, &ai, sizeof(ai));
	if (error)
		return (error);

	audit_arg_auditinfo(&ai);

	/*
	 * XXXRW: Test privilege while holding the proc lock?
	*/
	PROC_LOCK(td->td_proc);
	*td->td_proc->p_au = ai;
	PROC_UNLOCK(td->td_proc);

	return (0);
}

/* MPSAFE */
/* ARGSUSED */
int
getaudit_addr(struct thread *td, struct getaudit_addr_args *uap)
{
	int error;

	error = suser(td);
	if (error)
		return (error);
	return (ENOSYS);
}

/* MPSAFE */
/* ARGSUSED */
int
setaudit_addr(struct thread *td, struct setaudit_addr_args *uap)
{
	int error;

	error = suser(td);
	if (error)
		return (error);
	return (ENOSYS);
}

/*
 * MPSAFE
 * Syscall to manage audit files.
 *
 * XXX: Should generate an audit event.
 */
/* ARGSUSED */
int
auditctl(struct thread *td, struct auditctl_args *uap)
{
	struct nameidata nd;
	struct ucred *cred;
	struct vnode *vp;
	int error = 0;
	int flags;

	error = suser(td);
	if (error)
		return (error);

	vp = NULL;
	cred = NULL;

	/*
	 * If a path is specified, open the replacement vnode, perform
	 * validity checks, and grab another reference to the current
	 * credential.
	 *
	 * XXXAUDIT: On Darwin, a NULL path is used to disable audit.
	 */
	if (uap->path == NULL)
		return (EINVAL);

	/*
	 * XXXAUDIT: Giant may no longer be required here.
	 */
	mtx_lock(&Giant);
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE, uap->path, td);
	flags = AUDIT_OPEN_FLAGS;
	error = vn_open(&nd, &flags, 0, -1);
	if (error) {
		mtx_unlock(&Giant);
		goto err_out;
	}
	VOP_UNLOCK(nd.ni_vp, 0, td);
	vp = nd.ni_vp;
	if (vp->v_type != VREG) {
		vn_close(vp, AUDIT_CLOSE_FLAGS, td->td_ucred, td);
		mtx_unlock(&Giant);
		error = EINVAL;
		goto err_out;
	}
	cred = td->td_ucred;
	crhold(cred);

	/*
	 * XXXAUDIT: Should audit_suspended actually be cleared by
	 * audit_worker?
	 */
	audit_suspended = 0;

	mtx_unlock(&Giant);
	audit_rotate_vnode(cred, vp);

err_out:
	return (error);
}

#else /* !AUDIT */

int
audit(struct thread *td, struct audit_args *uap)
{

	return (ENOSYS);
}

int
auditon(struct thread *td, struct auditon_args *uap)
{

	return (ENOSYS);
}

int
getauid(struct thread *td, struct getauid_args *uap)
{

	return (ENOSYS);
}

int
setauid(struct thread *td, struct setauid_args *uap)
{

	return (ENOSYS);
}

int
getaudit(struct thread *td, struct getaudit_args *uap)
{

	return (ENOSYS);
}

int
setaudit(struct thread *td, struct setaudit_args *uap)
{

	return (ENOSYS);
}

int
getaudit_addr(struct thread *td, struct getaudit_addr_args *uap)
{

	return (ENOSYS);
}

int
setaudit_addr(struct thread *td, struct setaudit_addr_args *uap)
{

	return (ENOSYS);
}

int
auditctl(struct thread *td, struct auditctl_args *uap)
{

	return (ENOSYS);
}

void
audit_proc_init(struct proc *p)
{

}

void
audit_proc_fork(struct proc *parent, struct proc *child)
{

}

void
audit_proc_free(struct proc *p)
{

}

#endif /* AUDIT */
