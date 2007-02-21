/*
 * Copyright (c) 1999-2005 Apple Computer, Inc.
 * Copyright (c) 2006 Robert N. M. Watson
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
 * $FreeBSD: src/sys/security/audit/audit_worker.c,v 1.2 2006/03/19 17:34:00 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/ipc.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#include <bsm/audit.h>
#include <bsm/audit_internal.h>
#include <bsm/audit_kevents.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#include <security/audit/audit.h>
#include <security/audit/audit_private.h>

#include <vm/uma.h>

/*
 * Worker thread that will schedule disk I/O, etc.
 */
static struct proc		*audit_thread;

/*
 * When an audit log is rotated, the actual rotation must be performed by the
 * audit worker thread, as it may have outstanding writes on the current
 * audit log.  audit_replacement_vp holds the vnode replacing the current
 * vnode.  We can't let more than one replacement occur at a time, so if more
 * than one thread requests a replacement, only one can have the replacement
 * "in progress" at any given moment.  If a thread tries to replace the audit
 * vnode and discovers a replacement is already in progress (i.e.,
 * audit_replacement_flag != 0), then it will sleep on audit_replacement_cv
 * waiting its turn to perform a replacement.  When a replacement is
 * completed, this cv is signalled by the worker thread so a waiting thread
 * can start another replacement.  We also store a credential to perform
 * audit log write operations with.
 *
 * The current credential and vnode are thread-local to audit_worker.
 */
static struct cv		audit_replacement_cv;

static int			audit_replacement_flag;
static struct vnode		*audit_replacement_vp;
static struct ucred		*audit_replacement_cred;

/*
 * Flags related to Kernel->user-space communication.
 */
static int			audit_file_rotate_wait;

/*
 * XXXAUDIT: Should adjust comments below to make it clear that we get to
 * this point only if we believe we have storage, so not having space here is
 * a violation of invariants derived from administrative procedures. I.e.,
 * someone else has written to the audit partition, leaving less space than
 * we accounted for.
 */
static int
audit_record_write(struct vnode *vp, struct kaudit_record *ar,
    struct ucred *cred, struct thread *td)
{
	int ret;
	long temp;
	struct au_record *bsm;
	struct vattr vattr;
	struct statfs *mnt_stat = &vp->v_mount->mnt_stat;
	int vfslocked;

	vfslocked = VFS_LOCK_GIANT(vp->v_mount);

	/*
	 * First, gather statistics on the audit log file and file system so
	 * that we know how we're doing on space.  In both cases, if we're
	 * unable to perform the operation, we drop the record and return.
	 * However, this is arguably an assertion failure.
	 * XXX Need a FreeBSD equivalent.
	 */
	ret = VFS_STATFS(vp->v_mount, mnt_stat, td);
	if (ret)
		goto out;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, td);
	ret = VOP_GETATTR(vp, &vattr, cred, td);
	VOP_UNLOCK(vp, 0, td);
	if (ret)
		goto out;

	/* update the global stats struct */
	audit_fstat.af_currsz = vattr.va_size;

	/*
	 * XXX Need to decide what to do if the trigger to the audit daemon
	 * fails.
	 */

	/*
	 * If we fall below minimum free blocks (hard limit), tell the audit
	 * daemon to force a rotation off of the file system. We also stop
	 * writing, which means this audit record is probably lost.  If we
	 * fall below the minimum percent free blocks (soft limit), then
	 * kindly suggest to the audit daemon to do something.
	 */
	if (mnt_stat->f_bfree < AUDIT_HARD_LIMIT_FREE_BLOCKS) {
		(void)send_trigger(AUDIT_TRIGGER_NO_SPACE);
		/*
		 * Hopefully userspace did something about all the previous
		 * triggers that were sent prior to this critical condition.
		 * If fail-stop is set, then we're done; goodnight Gracie.
		 */
		if (audit_fail_stop)
			panic("Audit log space exhausted and fail-stop set.");
		else {
			audit_suspended = 1;
			ret = ENOSPC;
			goto out;
		}
	} else
		/*
		 * Send a message to the audit daemon that disk space is
		 * getting low.
		 *
		 * XXXAUDIT: Check math and block size calculation here.
		 */
		if (audit_qctrl.aq_minfree != 0) {
			temp = mnt_stat->f_blocks / (100 /
			    audit_qctrl.aq_minfree);
			if (mnt_stat->f_bfree < temp)
				(void)send_trigger(AUDIT_TRIGGER_LOW_SPACE);
		}

	/*
	 * Check if the current log file is full; if so, call for a log
	 * rotate. This is not an exact comparison; we may write some records
	 * over the limit. If that's not acceptable, then add a fudge factor
	 * here.
	 */
	if ((audit_fstat.af_filesz != 0) &&
	    (audit_file_rotate_wait == 0) &&
	    (vattr.va_size >= audit_fstat.af_filesz)) {
		audit_file_rotate_wait = 1;
		(void)send_trigger(AUDIT_TRIGGER_OPEN_NEW);
	}

	/*
	 * If the estimated amount of audit data in the audit event queue
	 * (plus records allocated but not yet queued) has reached the amount
	 * of free space on the disk, then we need to go into an audit fail
	 * stop state, in which we do not permit the allocation/committing of
	 * any new audit records.  We continue to process packets but don't
	 * allow any activities that might generate new records.  In the
	 * future, we might want to detect when space is available again and
	 * allow operation to continue, but this behavior is sufficient to
	 * meet fail stop requirements in CAPP.
	 */
	if (audit_fail_stop &&
	    (unsigned long)
	    ((audit_q_len + audit_pre_q_len + 1) * MAX_AUDIT_RECORD_SIZE) /
	    mnt_stat->f_bsize >= (unsigned long)(mnt_stat->f_bfree)) {
		printf("audit_record_write: free space below size of audit "
		    "queue, failing stop\n");
		audit_in_failure = 1;
	}

	/*
	 * If there is a user audit record attached to the kernel record,
	 * then write the user record.
	 *
	 * XXX Need to decide a few things here: IF the user audit record is
	 * written, but the write of the kernel record fails, what to do?
	 * Should the kernel record come before or after the user record?
	 * For now, we write the user record first, and we ignore errors.
	 */
	if (ar->k_ar_commit & AR_COMMIT_USER) {
		/*
		 * Try submitting the record to any active audit pipes.
		 */
		audit_pipe_submit((void *)ar->k_udata, ar->k_ulen);

		/*
		 * And to disk.
		 */
		ret = vn_rdwr(UIO_WRITE, vp, (void *)ar->k_udata, ar->k_ulen,
		    (off_t)0, UIO_SYSSPACE, IO_APPEND|IO_UNIT, cred, NULL,
		    NULL, td);
		if (ret)
			goto out;
	}

	/*
	 * Convert the internal kernel record to BSM format and write it out
	 * if everything's OK.
	 */
	if (!(ar->k_ar_commit & AR_COMMIT_KERNEL)) {
		ret = 0;
		goto out;
	}

	/*
	 * XXXAUDIT: Should we actually allow this conversion to fail?  With
	 * sleeping memory allocation and invariants checks, perhaps not.
	 */
	ret = kaudit_to_bsm(ar, &bsm);
	if (ret == BSM_NOAUDIT) {
		ret = 0;
		goto out;
	}

	/*
	 * XXX: We drop the record on BSM conversion failure, but really this
	 * is an assertion failure.
	 */
	if (ret == BSM_FAILURE) {
		AUDIT_PRINTF(("BSM conversion failure\n"));
		ret = EINVAL;
		goto out;
	}

	/*
	 * Try submitting the record to any active audit pipes.
	 */
	audit_pipe_submit((void *)bsm->data, bsm->len);

	/*
	 * XXX We should break the write functionality away from the BSM
	 * record generation and have the BSM generation done before this
	 * function is called. This function will then take the BSM record as
	 * a parameter.
	 */
	ret = (vn_rdwr(UIO_WRITE, vp, (void *)bsm->data, bsm->len, (off_t)0,
	    UIO_SYSSPACE, IO_APPEND|IO_UNIT, cred, NULL, NULL, td));
	kau_free(bsm);

out:
	/*
	 * When we're done processing the current record, we have to check to
	 * see if we're in a failure mode, and if so, whether this was the
	 * last record left to be drained.  If we're done draining, then we
	 * fsync the vnode and panic.
	 */
	if (audit_in_failure && audit_q_len == 0 && audit_pre_q_len == 0) {
		VOP_LOCK(vp, LK_DRAIN | LK_INTERLOCK, td);
		(void)VOP_FSYNC(vp, MNT_WAIT, td);
		VOP_UNLOCK(vp, 0, td);
		panic("Audit store overflow; record queue drained.");
	}

	VFS_UNLOCK_GIANT(vfslocked);

	return (ret);
}

/*
 * If an appropriate signal has been received rotate the audit log based on
 * the global replacement variables.  Signal consumers as needed that the
 * rotation has taken place.
 *
 * XXXRW: The global variables and CVs used to signal the audit_worker to
 * perform a rotation are essentially a message queue of depth 1.  It would
 * be much nicer to actually use a message queue.
 */
static void
audit_worker_rotate(struct ucred **audit_credp, struct vnode **audit_vpp,
    struct thread *audit_td)
{
	int do_replacement_signal, vfslocked;
	struct ucred *old_cred;
	struct vnode *old_vp;

	mtx_assert(&audit_mtx, MA_OWNED);

	do_replacement_signal = 0;
	while (audit_replacement_flag != 0) {
		old_cred = *audit_credp;
		old_vp = *audit_vpp;
		*audit_credp = audit_replacement_cred;
		*audit_vpp = audit_replacement_vp;
		audit_replacement_cred = NULL;
		audit_replacement_vp = NULL;
		audit_replacement_flag = 0;

		audit_enabled = (*audit_vpp != NULL);

		/*
		 * XXX: What to do about write failures here?
		 */
		if (old_vp != NULL) {
			AUDIT_PRINTF(("Closing old audit file\n"));
			mtx_unlock(&audit_mtx);
			vfslocked = VFS_LOCK_GIANT(old_vp->v_mount);
			vn_close(old_vp, AUDIT_CLOSE_FLAGS, old_cred,
			    audit_td);
			VFS_UNLOCK_GIANT(vfslocked);
			crfree(old_cred);
			mtx_lock(&audit_mtx);
			old_cred = NULL;
			old_vp = NULL;
			AUDIT_PRINTF(("Audit file closed\n"));
		}
		if (*audit_vpp != NULL) {
			AUDIT_PRINTF(("Opening new audit file\n"));
		}
		do_replacement_signal = 1;
	}

	/*
	 * Signal that replacement have occurred to wake up and
	 * start any other replacements started in parallel.  We can
	 * continue about our business in the mean time.  We
	 * broadcast so that both new replacements can be inserted,
	 * but also so that the source(s) of replacement can return
	 * successfully.
	 */
	if (do_replacement_signal)
		cv_broadcast(&audit_replacement_cv);
}

/*
 * Drain the audit commit queue and free the records.  Used if there are
 * records present, but no audit log target.
 */
static void
audit_worker_drain(void)
{
	struct kaudit_record *ar;

	while ((ar = TAILQ_FIRST(&audit_q))) {
		TAILQ_REMOVE(&audit_q, ar, k_q);
		audit_free(ar);
		audit_q_len--;
	}
}

/*
 * The audit_worker thread is responsible for watching the event queue,
 * dequeueing records, converting them to BSM format, and committing them to
 * disk.  In order to minimize lock thrashing, records are dequeued in sets
 * to a thread-local work queue.  In addition, the audit_work performs the
 * actual exchange of audit log vnode pointer, as audit_vp is a thread-local
 * variable.
 */
static void
audit_worker(void *arg)
{
	TAILQ_HEAD(, kaudit_record) ar_worklist;
	struct kaudit_record *ar;
	struct ucred *audit_cred;
	struct thread *audit_td;
	struct vnode *audit_vp;
	int error, lowater_signal;

	AUDIT_PRINTF(("audit_worker starting\n"));

	/*
	 * These are thread-local variables requiring no synchronization.
	 */
	TAILQ_INIT(&ar_worklist);
	audit_cred = NULL;
	audit_td = curthread;
	audit_vp = NULL;

	mtx_lock(&audit_mtx);
	while (1) {
		mtx_assert(&audit_mtx, MA_OWNED);

		/*
		 * Wait for record or rotation events.
		 */
		while (!audit_replacement_flag && TAILQ_EMPTY(&audit_q)) {
			AUDIT_PRINTF(("audit_worker waiting\n"));
			cv_wait(&audit_cv, &audit_mtx);
			AUDIT_PRINTF(("audit_worker woken up\n"));
			AUDIT_PRINTF(("audit_worker: new vp = %p; value of "
			    "flag %d\n", audit_replacement_vp,
			    audit_replacement_flag));
		}

		/*
		 * First priority: replace the audit log target if requested.
		 */
		audit_worker_rotate(&audit_cred, &audit_vp, audit_td);

		/*
		 * If we have records, but there's no active vnode to write
		 * to, drain the record queue.  Generally, we prevent the
		 * unnecessary allocation of records elsewhere, but we need
		 * to allow for races between conditional allocation and
		 * queueing.  Go back to waiting when we're done.
		 */
		if (audit_vp == NULL) {
			audit_worker_drain();
			continue;
		}

		/*
		 * We have both records to write and an active vnode to write
		 * to.  Dequeue a record, and start the write.  Eventually,
		 * it might make sense to dequeue several records and perform
		 * our own clustering, if the lower layers aren't doing it
		 * automatically enough.
		 */
		lowater_signal = 0;
		while ((ar = TAILQ_FIRST(&audit_q))) {
			TAILQ_REMOVE(&audit_q, ar, k_q);
			audit_q_len--;
			if (audit_q_len == audit_qctrl.aq_lowater)
				lowater_signal++;
			TAILQ_INSERT_TAIL(&ar_worklist, ar, k_q);
		}
		if (lowater_signal)
			cv_broadcast(&audit_commit_cv);

		mtx_unlock(&audit_mtx);
		while ((ar = TAILQ_FIRST(&ar_worklist))) {
			TAILQ_REMOVE(&ar_worklist, ar, k_q);
			if (audit_vp != NULL) {
				error = audit_record_write(audit_vp, ar,
				    audit_cred, audit_td);
				if (error && audit_panic_on_write_fail)
					panic("audit_worker: write error %d\n",
					    error);
				else if (error)
					printf("audit_worker: write error %d\n",
					    error);
			}
			audit_free(ar);
		}
		mtx_lock(&audit_mtx);
	}
}

/*
 * audit_rotate_vnode() is called by a user or kernel thread to configure or
 * de-configure auditing on a vnode.  The arguments are the replacement
 * credential and vnode to substitute for the current credential and vnode,
 * if any.  If either is set to NULL, both should be NULL, and this is used
 * to indicate that audit is being disabled.  The real work is done in the
 * audit_worker thread, but audit_rotate_vnode() waits synchronously for that
 * to complete.
 *
 * The vnode should be referenced and opened by the caller.  The credential
 * should be referenced.  audit_rotate_vnode() will own both references as of
 * this call, so the caller should not release either.
 *
 * XXXAUDIT: Review synchronize communication logic.  Really, this is a
 * message queue of depth 1.
 *
 * XXXAUDIT: Enhance the comments below to indicate that we are basically
 * acquiring ownership of the communications queue, inserting our message,
 * and waiting for an acknowledgement.
 */
void
audit_rotate_vnode(struct ucred *cred, struct vnode *vp)
{

	/*
	 * If other parallel log replacements have been requested, we wait
	 * until they've finished before continuing.
	 */
	mtx_lock(&audit_mtx);
	while (audit_replacement_flag != 0) {
		AUDIT_PRINTF(("audit_rotate_vnode: sleeping to wait for "
		    "flag\n"));
		cv_wait(&audit_replacement_cv, &audit_mtx);
		AUDIT_PRINTF(("audit_rotate_vnode: woken up (flag %d)\n",
		    audit_replacement_flag));
	}
	audit_replacement_cred = cred;
	audit_replacement_flag = 1;
	audit_replacement_vp = vp;

	/*
	 * Wake up the audit worker to perform the exchange once we
	 * release the mutex.
	 */
	cv_signal(&audit_cv);

	/*
	 * Wait for the audit_worker to broadcast that a replacement has
	 * taken place; we know that once this has happened, our vnode
	 * has been replaced in, so we can return successfully.
	 */
	AUDIT_PRINTF(("audit_rotate_vnode: waiting for news of "
	    "replacement\n"));
	cv_wait(&audit_replacement_cv, &audit_mtx);
	AUDIT_PRINTF(("audit_rotate_vnode: change acknowledged by "
	    "audit_worker (flag " "now %d)\n", audit_replacement_flag));
	mtx_unlock(&audit_mtx);

	audit_file_rotate_wait = 0; /* We can now request another rotation */
}

void
audit_worker_init(void)
{
	int error;

	cv_init(&audit_replacement_cv, "audit_replacement_cv");
	error = kthread_create(audit_worker, NULL, &audit_thread, RFHIGHPID,
	    0, "audit_worker");
	if (error)
		panic("audit_worker_init: kthread_create returned %d", error);
}
