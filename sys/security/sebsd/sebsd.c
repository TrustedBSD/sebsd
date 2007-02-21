/*-
 * Copyright (c) 2002, 2003 Networks Associates Technology, Inc.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by NAI Labs, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
#include <sys/extattr.h>
#include <sys/imgact.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/pipe.h>
#include <sys/dirent.h>
#include <sys/capability.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sx.h>

#include <posix4/ksem.h>

#include <fs/devfs/devfs.h>

#include <vm/vm.h>

#include <sys/mac_policy.h>

#include <security/sebsd/sebsd.h>
#include <security/sebsd/sebsd_labels.h>

int	sebsd_verbose = 0;

static int slot;
#define	SLOT(l)	((void *)LABEL_TO_SLOT((l), slot).l_ptr)

MALLOC_DEFINE(M_SEBSD, "sebsd", "Security Enhanced BSD");

static void
sebsd_init(struct mac_policy_conf *mpc)
{
	printf("sebsd:: init\n");
	avc_init();
	if (security_init()) {
		panic("SEBSD: couldn't read policy file");
	}
}

static void
sebsd_destroy(struct mac_policy_conf *mpc)
{

	panic("sebsd_destroy");
}

static int
signal_to_av(int signum)
{
        uint32_t perm;

        switch (signum) {
                case SIGCHLD:
                        perm = PROCESS__SIGCHLD;
                        break;
                case SIGKILL:
                        perm = PROCESS__SIGKILL;
                        break;
                case SIGSTOP:
                        perm = PROCESS__SIGSTOP;
                        break;
                default:
                        perm = PROCESS__SIGNAL;
                        break;
                }
        return perm;
}

static void
copy_network_label(struct label *src, struct label *dest)
{
	if (src == NULL)
		printf("copy_network_label: src is NULL\n");
	if (dest == NULL)
		printf("copy_network_label: dest is NULL\n");
	if (SLOT(dest) == NULL)
		printf("copy_network_label: slot(dest) is NULL\n");
	if (SLOT(src) == NULL)
		printf("copy_network_label: slot(src) is NULL\n");
	
	*(struct network_security_struct *) SLOT(dest) =
	    *(struct network_security_struct *) SLOT(src);
}

/*
 * Check whether a task is allowed to use a capability.
 */
static int
cred_has_capability(struct ucred *cred, cap_value_t cap)
{
	struct task_security_struct *task;
	struct avc_audit_data ad;

	task = SLOT(cred->cr_label);

	AVC_AUDIT_DATA_INIT(&ad, CAP);
	ad.u.cap = cap;

	return (avc_has_perm(task->sid, task->sid,
	    SECCLASS_CAPABILITY, cap, &ad));
}

static int
cred_has_perm(struct ucred *cred, struct proc *proc, u_int32_t perm)
{
	struct task_security_struct *task, *target;

	task = SLOT(cred->cr_label);
	target = SLOT(proc->p_ucred->cr_label);

	return (avc_has_perm(task->sid, target->sid,
	    SECCLASS_PROCESS, perm, NULL));
}

static int
mount_has_perm(struct ucred *cred, struct mount *mp, u_int32_t perm,
    struct avc_audit_data *ad)
{
	struct mount_security_struct *sbsec;
	struct task_security_struct *task;

	task = SLOT(cred->cr_label);
	sbsec = SLOT(mp->mnt_mntlabel);

	return (avc_has_perm(task->sid, sbsec->sid, SECCLASS_FILESYSTEM,
	    perm, ad));
}

static int
cred_has_system(struct ucred *cred, u_int32_t perm)
{
	struct task_security_struct *task;

	task = SLOT(cred->cr_label);

	return (avc_has_perm(task->sid, SECINITSID_KERNEL,
	    SECCLASS_SYSTEM, perm, NULL));
}

static int
cred_has_security(struct ucred *cred, u_int32_t perm)
{
	struct task_security_struct *task;

	task = SLOT(cred->cr_label);

	return (avc_has_perm(task->sid, SECINITSID_SECURITY,
	    SECCLASS_SECURITY, perm, NULL));
}

int
thread_has_system(struct thread *td, u_int32_t perm)
{

	return (cred_has_system(td->td_proc->p_ucred, perm));
}

int
thread_has_security(struct thread *td, u_int32_t perm)
{

	return (cred_has_security(td->td_proc->p_ucred, perm));
}

static __inline u_int16_t
vnode_type_to_security_class(enum vtype vt)
{

	switch (vt) {
	case VREG:
		return (SECCLASS_FILE);
	case VDIR:
		return (SECCLASS_DIR);
	case VBLK:
		return (SECCLASS_BLK_FILE);
	case VCHR:
		return (SECCLASS_CHR_FILE);
	case VLNK:
		return (SECCLASS_LNK_FILE);
	case VSOCK:
		return (SECCLASS_SOCK_FILE);
	case VFIFO:
		return (SECCLASS_FIFO_FILE);
	case VNON:
	case VBAD:
		return (SECCLASS_FILE);
	case VMARKER:
		panic("vnode_type_to_security_class: VMARKER");
	}

	return (SECCLASS_FILE);
}

static __inline u_int16_t
dirent_type_to_security_class(__uint8_t type)
{

	switch (type) {
	case DT_REG:
		return (SECCLASS_FILE);
	case DT_DIR:
		return (SECCLASS_DIR);
	case DT_BLK:
		return (SECCLASS_BLK_FILE);
	case DT_CHR:
		return (SECCLASS_CHR_FILE);
	case DT_LNK:
		return (SECCLASS_LNK_FILE);
	case DT_SOCK:
		return (SECCLASS_SOCK_FILE);
	case DT_FIFO:
		return (SECCLASS_FIFO_FILE);
	case DT_UNKNOWN:
	case DT_WHT:
		return (SECCLASS_FILE);
	}

	return (SECCLASS_FILE);
}

static __inline u_int32_t
file_mask_to_av(enum vtype vt, int mask)
{
	u_int32_t av = 0;

	if (vt != VDIR) {
		if (mask & VEXEC)
			av |= FILE__EXECUTE;
		if (mask & VREAD)
			av |= FILE__READ;

		if (mask & VAPPEND)
			av |= FILE__APPEND;
		else if (mask & VWRITE)
			av |= FILE__WRITE;
	} else {
		if (mask & VEXEC)
			av |= DIR__SEARCH;
		if (mask & VWRITE)
			av |= DIR__WRITE;
		if (mask & VREAD)
			av |= DIR__READ;
	}

	return (av);
}

static int
vnode_has_perm(struct ucred *cred, struct vnode *vp, u_int32_t perm)
{
	struct task_security_struct *task;
	struct vnode_security_struct *file;
	struct avc_audit_data ad;

	task = SLOT(cred->cr_label);
	file = SLOT(vp->v_label);

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;

	if (file->sclass == 0) {
		struct vattr va;
		VOP_GETATTR(vp, &va, curthread->td_ucred, curthread);
		printf("vnode_has_perm:: ERROR, sid=%d, sclass=0, v_type=%d,"
		       " inode=%ld, fsid=%d\n",
		       file->sid, vp->v_type, va.va_fileid, va.va_fsid);
		file->sclass = vnode_type_to_security_class(vp->v_type);
		if (file->sclass == 0) {
			printf("vnode_has_perm:: Giving up\n");
			return (1);	/* TBD: debugging */
		}
	}
	return (avc_has_perm(task->sid, file->sid, file->sclass, perm, &ad));
}

static int
pipe_has_perm(struct ucred *cred, struct pipepair *pp, u_int32_t perm)
{
	struct task_security_struct *task;
	struct vnode_security_struct *file;

	task = SLOT(cred->cr_label);
	file = SLOT(pp->pp_label);

	/*
	 * TBD: No audit information yet
	 */

	return (avc_has_perm(task->sid, file->sid, file->sclass, perm, NULL));
}

static void
sebsd_init_cred_label(struct label *label)
{
	struct task_security_struct *new_tsec;

	new_tsec = sebsd_malloc(sizeof(*new_tsec), M_SEBSD, M_ZERO | M_WAITOK);
	new_tsec->osid = new_tsec->sid = SECINITSID_UNLABELED;
	SLOT(label) = new_tsec;
}

static void
sebsd_init_file_label(struct label *label)
{
	struct file_security_struct *new_fsec;

	new_fsec = sebsd_malloc(sizeof(*new_fsec), M_SEBSD, M_ZERO | M_WAITOK);
	new_fsec->sid = new_fsec->sid = SECINITSID_UNLABELED;
	SLOT(label) = new_fsec;
}

static void
sebsd_init_mount_label(struct label *label)
{
	struct mount_security_struct *sbsec;

	sbsec = sebsd_malloc(sizeof(*sbsec), M_SEBSD, M_ZERO | M_WAITOK);
	sbsec->sid = SECINITSID_UNLABELED;
	SLOT(label) = sbsec;
}

static void
sebsd_init_mount_fs_label(struct label *label)
{
	struct mount_fs_security_struct *sbsec;

	sbsec = sebsd_malloc(sizeof(*sbsec), M_SEBSD, M_ZERO | M_WAITOK);
	sbsec->sid = SECINITSID_UNLABELED;
	SLOT(label) = sbsec;
}

static void
sebsd_init_network_label(struct label *label)
{
	struct network_security_struct *new;

	new = sebsd_malloc(sizeof(*new), M_SEBSD, M_ZERO | M_WAITOK);
	new->sid = new->task_sid = SECINITSID_UNLABELED;
	SLOT(label) = new;
}

static int
sebsd_init_network_label_waitcheck(struct label *label, int flag)
{
	struct network_security_struct *new;

	new = sebsd_malloc(sizeof(*new), M_SEBSD, M_ZERO | flag);
	if (new == NULL) {
		SLOT(label) = NULL;
		return (ENOMEM);
	}

	new->sid = new->task_sid = SECINITSID_UNLABELED;
	SLOT(label) = new;

	return (0);
}

static void
sebsd_init_vnode_label(struct label *label)
{
	struct vnode_security_struct *vsec;

	vsec = sebsd_malloc(sizeof(*vsec), M_SEBSD, M_ZERO | M_WAITOK);
	vsec->sid = SECINITSID_UNLABELED;
	vsec->task_sid = SECINITSID_UNLABELED;
	SLOT(label) = vsec;
}

static void
sebsd_init_sysv_label(struct label *label)
{
	struct ipc_security_struct *new;

	new = sebsd_malloc(sizeof(*new), M_SEBSD, M_ZERO | M_WAITOK);
	new->sid = SECINITSID_UNLABELED;
	SLOT(label) = new;
}

static void
sebsd_destroy_label(struct label *label)
{

	sebsd_free(SLOT(label), M_SEBSD);
	SLOT(label) = NULL;
}

static void
sebsd_relabel_cred(struct ucred *cred, struct label *newlabel)
{

	printf("sebsd_relabel_cred:: This does nothing\n");
}

static void
sebsd_relabel_ifnet(struct ucred *cred, struct ifnet *ifn,
    struct label *ilabel, struct label *newlabel)
{

	copy_network_label(newlabel, ilabel);
}

static void
sebsd_cleanup_sysv_label(struct label *label)
{
	struct ipc_security_struct *ipcsec;

	ipcsec = SLOT(label);
	bzero(ipcsec, sizeof(struct ipc_security_struct));
	ipcsec->sid = SECINITSID_UNLABELED;
}

static void
sebsd_associate_vnode_devfs(struct mount *mp, struct label *fslabel,
    struct devfs_dirent *de, struct label *delabel, struct vnode *vp,
    struct label *vlabel)
{
	struct vnode_security_struct *vsec, *dsec;

	dsec = SLOT(delabel);
	vsec = SLOT(vlabel);

	vsec->sid = dsec->sid;
	vsec->task_sid = dsec->task_sid;
	vsec->sclass = dsec->sclass;

	/*
	 * This is a no-op for now, but when devfs_dirents do contain
	 * labels, they should be copied to the vp here as per how
	 * sebsd_update_vnode_from_extattr() functions.  They will be
	 * kept synchronized from here on automatically with the vnode
	 * relabel calls.
	 */
}

static void
sebsd_update_devfsdirent(struct mount *mp, struct devfs_dirent *de,
    struct label *delabel, struct vnode *vp, struct label *vlabel)
{
	struct vnode_security_struct *vsec, *dsec;

	vsec = SLOT(vlabel);
	dsec = SLOT(delabel);

	dsec->sid = vsec->sid;
	dsec->task_sid = vsec->task_sid;
	dsec->sclass = vsec->sclass;
}

static int
sebsd_associate_vnode_extattr(struct mount *mp, struct label *fslabel,
    struct vnode *vp, struct label *vlabel)
{
	struct vnode_security_struct *vsec;
	/* TBD: Need to limit size of contexts used in extattr labels */
	char context[128];
	u_int32_t context_len;
	int error;

	vsec = SLOT(vlabel);

	context_len = sizeof(context); /* TBD: bad fixed length */
	error = vn_extattr_get(vp, IO_NODELOCKED,
	    SEBSD_MAC_EXTATTR_NAMESPACE, SEBSD_MAC_EXTATTR_NAME,
	    &context_len, context, curthread);
	if (error == ENOATTR || error == EOPNOTSUPP) {
		vsec->sid = SECINITSID_UNLABELED; /* Use the default label */

#if 0
		struct vattr va;

		(void)VOP_GETATTR(vp, &va, curthread->td_ucred, curthread);
		printf("sebsd_update_vnode_from_extattr: no label for "
		       "inode=%ld, fsid=%d\n", va.va_fileid, va.va_fsid);
#endif
		goto dosclass;
	}
	if (error) {
		printf("sebsd_update_vnode_from_extattr: ERROR %d returned "
		    " by vn_extattr_get()\n", error);
		return (error); /* Fail closed */
	}
	if (sebsd_verbose > 1) {
		struct vattr va;

		VOP_GETATTR(vp, &va, curthread->td_ucred, curthread);
		printf("sebsd_vnode_from_extattr: len=%d: context=%.*s "
		       "inode=%ld, fsid=%d\n", context_len, context_len,
			context, va.va_fileid, va.va_fsid);
	}

	error = security_context_to_sid(context, context_len, &vsec->sid);
	if (error) {
		printf("sebsd_update_vnode_from_extattr: ERROR mapping "
		       "context to sid: %.*s\n", context_len, context);
		return (0);	/* TBD bad, bad, bad */
	}

dosclass:
	/* TBD:	 */
 	vsec->sclass = vnode_type_to_security_class(vp->v_type);
	if (vsec->sclass == 0)
		printf("sebsd_update_vnode_from_extattr:: sclass is 0\n");

	return (0);
}

static void
sebsd_associate_vnode_singlelabel(struct mount *mp, struct label *fslabel,
    struct vnode *vp, struct label *vlabel)
{
	struct mount_fs_security_struct *sbsec;
	struct vnode_security_struct *vsec;

	sbsec = SLOT(fslabel);
	vsec = SLOT(vlabel);
	vsec->sid = sbsec->sid;
 	vsec->sclass = vnode_type_to_security_class(vp->v_type);
}

static void
sebsd_copy_cred_label(struct label *src, struct label *dest)
{
	struct task_security_struct *parent, *task;

	parent = SLOT(src);
	task = SLOT(dest);

	/* Default to using the attributes from the parent process */
	task->osid = parent->osid;
	task->sid = parent->sid;
}

static void
sebsd_create_file(struct ucred *cred, struct file *fp, struct label *label)
{
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	tsec = SLOT(cred->cr_label);
	fsec = SLOT(label);

	fsec->sid = tsec->sid;
}

#if 0
static void
sebsd_create_fragment(struct mbuf *datagram, struct label *dlabel,
    struct mbuf *frag, struct label *flabel)
{

	copy_network_label(dlabel, flabel);
}
#endif

/*
 * XXX: What's are sensible values to assign to an interface?
 */
static void
sebsd_create_ifnet(struct ifnet *ifn, struct label *iflabel)
{

	struct network_security_struct *nsec;

	nsec = SLOT(iflabel);
	nsec->sid = 0;
	nsec->task_sid = 0;
}

static void
sebsd_create_inpcb_from_socket(struct socket *so, struct label *solabel,
    struct inpcb *inp, struct label *ilabel)
{
	
	copy_network_label(solabel, ilabel);
}

#if 0
static void 
sebsd_create_ipq(struct mbuf *frag, struct label *fraglabel, struct ipq *ipq,
    struct label *ipqlabel)
{

	copy_network_label(fraglabel, ipqlabel);
} 

static void
sebsd_create_mbuf_from_bpfdesc(struct bpf_d *b, struct label *blabel,
    struct mbuf *m, struct label *mlabel)
{

	copy_network_label(blabel, mlabel);
}

static void
sebsd_create_mbuf_from_ifnet(struct ifnet *ifn, struct label *ilabel,
    struct mbuf *m, struct label *mlabel)
{

	copy_network_label(ilabel, mlabel);
}

static void
sebsd_create_mbuf_from_inpcb(struct inpcb *in, struct label *ilabel, 
    struct mbuf *m, struct label *mlabel)
{

	copy_network_label(ilabel, mlabel);
}

static void
sebsd_create_mbuf_linklayer(struct ifnet *ifn, struct label *iflabel,
    struct mbuf *m, struct label *mlabel)
{

	copy_network_label(iflabel, mlabel);
}

static void
sebsd_create_mbuf_netlayer(struct mbuf *oldmbuf, struct label *oldlabel,
    struct mbuf *newmbuf, struct label *newlabel)
{

	copy_network_label(oldlabel, newlabel);
}

static void
sebsd_create_mbuf_multicast_encap(struct mbuf *oldmbuf, struct label *oldlabel,
    struct ifnet *ifn, struct label *iflabel, struct mbuf *newmbuf,
    struct label *newlabel)
{

	copy_network_label(oldlabel, newlabel);
}

static void
sebsd_create_datagram_from_ipq(struct ipq *ipq, struct label *ipqlabel,
    struct mbuf *datagram, struct label *datagramlabel)
{

	copy_network_label(ipqlabel, datagramlabel);
}
#endif

static void
sebsd_create_sysv_msgmsg(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqlabel, struct msg *msgptr, struct label *msglabel)
{
	struct task_security_struct *tsec;
	struct ipc_security_struct *msqsec;
	struct ipc_security_struct *msgsec;

	tsec = SLOT(cred->cr_label);
	msqsec = SLOT(msqlabel);
	msgsec = SLOT(msglabel);

	bzero(msgsec, sizeof(*msgsec));
	msgsec->sclass = SECCLASS_MSG;

	/*
	 * XXX should we return an error if security_transition_sid, or,
	 * should we assign the msg object the thread sid?
	 */
	if (security_transition_sid(tsec->sid, msqsec->sid,
	    SECCLASS_MSG, &msgsec->sid) < 0) {
		printf("Warning: security_transition_sid failed on"
				"create_sysv_msgmsg\n");
		printf("Assigning the requesting thread's sid to the msg\n");
		msgsec->sid = tsec->sid;
	}
}

static void
sebsd_create_sysv_msgqueue(struct ucred *cred, struct msqid_kernel *msqkptr,
   struct label *msqlabel)
{
	struct task_security_struct *tsec;
	struct ipc_security_struct *ipcsec;

	tsec = SLOT(cred->cr_label);
	ipcsec = SLOT(msqlabel);

	ipcsec->sid = tsec->sid;
	ipcsec->sclass = SECCLASS_MSGQ;
}

static void
sebsd_create_sysv_sem(struct ucred *cred, struct semid_kernel *semakptr,
   struct label *semalabel)
{
	struct task_security_struct *tsec;
	struct ipc_security_struct *ipcsec;

	tsec = SLOT(cred->cr_label);
	ipcsec = SLOT(semalabel);

	ipcsec->sid = tsec->sid;
	ipcsec->sclass = SECCLASS_SEM;
}

static void
sebsd_create_sysv_shm(struct ucred *cred, struct shmid_kernel *shmsegptr,
   struct label *shmlabel)
{
	struct task_security_struct *tsec;
	struct ipc_security_struct *ipcsec;

	tsec = SLOT(cred->cr_label);
	ipcsec = SLOT(shmlabel);

	ipcsec->sid = tsec->sid;
	ipcsec->sclass = SECCLASS_SHM;
}

static void
sebsd_create_posix_sem(struct ucred *cred, struct ksem *ksemptr,
    struct label *ks_label)
{
	struct task_security_struct *tsec;
	struct ipc_security_struct *ipcsec;

	tsec = SLOT(cred->cr_label);
	ipcsec = SLOT(ks_label);

	ipcsec->sid = tsec->sid;
	ipcsec->sclass = SECCLASS_SEM;
}

static void
sebsd_create_bpfdesc(struct ucred *cred, struct bpf_d *b,
    struct label *blabel)
{
	struct network_security_struct *nsec;
	struct task_security_struct *tsec;

	nsec = SLOT(blabel);
	tsec = SLOT(cred->cr_label);

	nsec->sid = nsec->task_sid = tsec->sid;
}

static void
sebsd_create_devfs_device(struct ucred *cr, struct mount *mp,
    struct cdev *dev, struct devfs_dirent *devfs_dirent, struct label *label,
    const char *fullpath)
{
	char *path;
	int rc;
	u_int32_t newsid;
	struct mount_security_struct *sbsec;
	struct vnode_security_struct *dirent;

	dirent = SLOT(label);
	sbsec = SLOT(mp->mnt_mntlabel);

	/* Default to the filesystem SID. */
	dirent->sid = sbsec->sid;
	dirent->task_sid = SECINITSID_KERNEL;
	dirent->sclass =
	    dirent_type_to_security_class(devfs_dirent->de_dirent->d_type);

	/* Obtain a SID based on the fstype, path, and class. */
	if (fullpath != NULL) {
		path = sebsd_malloc(strlen(fullpath) + 2, M_SEBSD,
		    M_ZERO | M_WAITOK);
		path[0] = '/';
		strcpy(&path[1], fullpath);
	} else
		path = "/";
	rc = security_genfs_sid(mp->mnt_vfc->vfc_name, path, dirent->sclass,
	    &newsid);

	if (rc == 0)
		dirent->sid = newsid;

	/* If there was a creating process (currently only for /dev/pty*),
	   try a type_transition rule. */
	if (cr != NULL) {
		struct task_security_struct *task = SLOT(cr->cr_label);

		/*
		 * XXX: uses the type specified by genfs instead of the
		 * parent directory like it should!
		 */
		int error = security_transition_sid(task->sid, dirent->sid,
		    dirent->sclass, &newsid);
		if (error == 0)
			dirent->sid = newsid;
	}

	/* TBD: debugging */
	if (sebsd_verbose > 1) {
		printf("sebsd_create_devfs_device(%s): sbsid=%d, "
		    "mountpoint=%s, rc=%d, sclass=%d, computedsid=%d, "
		    "dirent=%d\n", path, sbsec->sid, mp->mnt_stat.f_mntonname,
		    rc, dirent->sclass, newsid, dirent->sid);
	}
	if (fullpath != NULL)
		sebsd_free(path, M_SEBSD);
}

static void
sebsd_create_devfs_directory(struct mount *mp, char *dirname, int dirnamelen,
    struct devfs_dirent *devfs_dirent, struct label *label,
    const char *fullpath)
{
	char *path;
	int rc;
	u_int32_t newsid;
	struct mount_security_struct *sbsec;
	struct vnode_security_struct *dirent;

	dirent = SLOT(label);
	sbsec = SLOT(mp->mnt_mntlabel);

	/* Default to the filesystem SID. */
	dirent->sid = sbsec->sid;
	dirent->task_sid = SECINITSID_KERNEL;
	dirent->sclass = SECCLASS_DIR;

	/* Obtain a SID based on the fstype, path, and class. */
	if (fullpath != NULL) {
		path = sebsd_malloc(strlen(fullpath) + 2, M_SEBSD,
		    M_ZERO | M_WAITOK);
		path[0] = '/';
		strcpy(&path[1], fullpath);
	} else
		path = "/";
	rc = security_genfs_sid(mp->mnt_vfc->vfc_name, path, dirent->sclass,
	    &newsid);
	if (rc == 0)
		dirent->sid = newsid;

	/* TBD: debugging */
	if (sebsd_verbose > 1) {
		printf("%s(%s): sbsid=%d, mountpoint=%s, "
		    "rc=%d, sclass=%d, computedsid=%d, dirent=%d\n",
		    __func__, path, sbsec->sid, mp->mnt_stat.f_mntonname, rc,
		    dirent->sclass, newsid, dirent->sid);
	}
	if (fullpath != NULL)
		sebsd_free(path, M_SEBSD);
}

static void
sebsd_create_devfs_symlink(struct ucred *cred, struct mount *mp,
    struct devfs_dirent *dd, struct label *ddlabel, struct devfs_dirent *de,
    struct label *delabel, const char *fullpath)
{
	char *path;
	int rc;
	u_int32_t newsid;
	struct vnode_security_struct *lnksec;
	struct vnode_security_struct *dirsec;
	struct mount_security_struct *sbsec;

	/* TBD: Should probably be checking MAY_LINK/MAY_CREATE perms here */

	dirsec = SLOT(ddlabel);
	lnksec = SLOT(delabel);
	sbsec = SLOT(mp->mnt_mntlabel);

	/* Default to the filesystem SID. */
	lnksec->sid = dirsec->sid;
	lnksec->task_sid = SECINITSID_KERNEL;
	lnksec->sclass = SECCLASS_LNK_FILE;

	/* Obtain a SID based on the fstype, path, and class. */
	if (fullpath != NULL) {
		path = sebsd_malloc(strlen(fullpath) + 2, M_SEBSD,
		    M_ZERO | M_WAITOK);
		path[0] = '/';
		strcpy(&path[1], fullpath);
	} else
		path = "/";
	rc = security_genfs_sid(mp->mnt_vfc->vfc_name, path, lnksec->sclass,
	    &newsid);
	if (rc == 0)
		lnksec->sid = newsid;

	if (sebsd_verbose > 1) {
		printf("%s(%s): sbsid=%d, mountpoint=%s, rc=%d, sclass=%d, "
		    "computedsid=%d, dirent=%d\n", __func__, path,
		    sbsec->sid, mp->mnt_stat.f_mntonname, rc,
		    lnksec->sclass, newsid, lnksec->sid);
	}
	if (fullpath != NULL)
		sebsd_free(path, M_SEBSD);
}

/*
 * Use the allocating task SID to label pipes.  On Linux, pipes reside in a
 * pseudo filesystem.
 */
static void
sebsd_create_pipe(struct ucred *cred, struct pipepair *pipe,
   struct label *pipelabel)
{
	struct task_security_struct *tsec;
	struct vnode_security_struct *vsec;

	tsec = SLOT(cred->cr_label);
	vsec = SLOT(pipelabel);

	vsec->sid = vsec->task_sid = tsec->sid;
	vsec->sclass = SECCLASS_FIFO_FILE;
}

static void
sebsd_create_kernel_proc(struct ucred *cred)
{
	struct task_security_struct *task;

	task = SLOT(cred->cr_label);
	task->osid = task->sid = SECINITSID_KERNEL;
	printf("%s:: using SECINITSID_KERNEL = %d\n", __func__,
	    SECINITSID_KERNEL);
}

#if 0
static void
sebsd_create_mbuf_from_socket(struct socket *so, struct label *solabel,
    struct mbuf *m, struct label *mlabel)
{

	copy_network_label(solabel, mlabel);
}
#endif

static void
sebsd_create_mount(struct ucred *cred, struct mount *mp,
    struct label *mntlabel, struct label *fslabel,
    struct label *mount_arg_label)
{
	struct mount_security_struct *sbsec, *mntsec;
	struct mount_fs_security_struct *sbfssec;
	int behavior, rc;

	sbsec = SLOT(mntlabel);
	sbfssec = SLOT(fslabel);
	/* TBD TBD TBD */
	/*
	 * Make the label for the filesystem the same as the singlelabel
	 * which the filesystem will use if not a "multilabel" type.
	 */
	rc = security_fs_use(mp->mnt_vfc->vfc_name, &behavior, &sbsec->sid);
	if (rc) {
		printf("sebsd_create_mount: security_fs_use(%s) returned %d\n",
		    mp->mnt_vfc->vfc_name, rc);
		behavior = SECURITY_FS_USE_NONE;
	} else {
		sbfssec->sid = sbsec->sid;
		/* TBD: debugging only */
		printf("sebsd_create_mount: security_fs_use(%s) behavior "
		    "%d, sid %d\n", mp->mnt_vfc->vfc_name, behavior,
		    sbsec->sid);
	}

	switch (behavior) {
	case SECURITY_FS_USE_XATTR:
		/*
		 * PSIDs only work for persistent file systems with unique
		 * and persistent inode numbers.
		 */
		sbsec->uses_psids = 1;

		/*
		 * TBD: need to correctly label mountpoint with persistent
		 * label at this point (currently vnode is unavailable)
		 */

		break;
	case SECURITY_FS_USE_TRANS:
		/*
		 * Transition SIDs are used for pseudo filesystems like
		 * devpts and tmpfs where you want the SID to be derived
		 * from the SID of the creating process and the SID of the
		 * filesystem.
		 */
		sbsec->uses_trans = 1;
		break;
	case SECURITY_FS_USE_TASK:
		/*
		 * Task SIDs are used for pseudo filesystems like pipefs and
		 * sockfs where you want the objects to be labeled with the
		 * SID of the creating process.
		 */
		sbsec->uses_task = 1;
		break;
	case SECURITY_FS_USE_GENFS:
		/*
		 * genfs_contexts handles everything else, like devfs,
		 * usbdevfs, driverfs, and portions of proc.
		 */
		sbsec->uses_genfs = 1;
		break;
	case SECURITY_FS_USE_NONE:
		/*
		 * No labeling support configured for this filesystem type.
		 * Don't appear to require labeling for binfmt_misc, bdev,
		 * or rootfs.
		 */
		break;
	default:
		printf("%s:  security_fs_use(%s) returned unrecognized "
		    "behavior %d\n", __FUNCTION__, mp->mnt_vfc->vfc_name,
		    behavior);
		behavior = SECURITY_FS_USE_NONE;
		break;
	}

	if (mount_arg_label) {
		mntsec = SLOT(mount_arg_label);
		sbsec->sid = mntsec->sid;
	}
}

static void
sebsd_create_socket(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct task_security_struct *tsec;
	struct network_security_struct *nsec;

	tsec = SLOT(cred->cr_label);
	nsec = SLOT(solabel);
	nsec->sid = nsec->task_sid = tsec->sid;
}

static void
sebsd_create_socket_from_socket(struct socket *olds, struct label *oldslabel,
    struct socket *news, struct label *newslabel)
{

	copy_network_label(oldslabel, newslabel);
}

static int
sebsd_create_vnode_extattr(struct ucred *cred, struct mount *mp,
    struct label *fslabel, struct vnode *parent, struct label *parentlabel,
    struct vnode *child, struct label *childlabel, struct componentname *cnp)
{
	struct vnode_security_struct *dir, *vsec;
	struct task_security_struct *task;
	char *context;
	u_int32_t context_len;
	u_int32_t newsid;
	int error;
	int tclass;

 	task = SLOT(cred->cr_label);
	dir = SLOT(parentlabel);
	vsec = SLOT(childlabel);
	tclass = vnode_type_to_security_class(child->v_type);

	error = security_transition_sid(task->sid, dir->sid, tclass, &newsid);
	if (error)
		return (error);

	vsec->sid = newsid;
	vsec->task_sid = task->sid;
	vsec->sclass = tclass;

	/* store label in vnode */
	error = security_sid_to_context(vsec->sid, &context, &context_len);
	if (error)
		return (error);

	error = vn_extattr_set(child, IO_NODELOCKED,
	    SEBSD_MAC_EXTATTR_NAMESPACE, SEBSD_MAC_EXTATTR_NAME,
	    context_len, context, curthread);

	security_free_context(context);
	return (error);
}	

#if 0
static void
sebsd_update_ipq(struct mbuf *frag, struct label *fraglabel, struct ipq *ipq,
    struct label *ipqlabel)
{

	copy_network_label(fraglabel, ipqlabel);
}
#endif

static void
sebsd_inpcb_sosetlabel(struct socket *so, struct label *solabel,
    struct inpcb *inp, struct label *ilabel)
{

	copy_network_label(solabel, ilabel);
}

static int
sebsd_check_cap(struct ucred *cred, cap_value_t capv)
{

	return (cred_has_capability(cred, capv));
}

/*
 * SEBSD does not support the relabeling of processes without transitioning.
 */
static int
sebsd_check_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	struct task_security_struct *nsec, *tsec;

	nsec = SLOT(newlabel);
	tsec = SLOT(cred->cr_label);
	if (nsec != NULL && nsec->sid != tsec->sid)
		return (EPERM);
	return (0);
}

static int
sebsd_check_mount(struct ucred *cred, struct vnode *vp, struct label *vl,
    const char *vfc_name, struct label *mntlabel)
{
	int rc;
	u_int32_t sid;
	int behavior;
	struct vnode_security_struct *vsec;
	struct task_security_struct  *task;
	struct mount_security_struct *sbsec;

	vsec = SLOT(vl);
	task = SLOT(cred->cr_label);

	rc = vnode_has_perm(cred, vp, FILE__MOUNTON);
	if (rc)
		return (rc);

	if (mntlabel) {
		sbsec = SLOT(mntlabel);
		sid = sbsec->sid;

		rc = avc_has_perm(task->sid, sid, SECCLASS_FILE,
		    COMMON_FILE__RELABELTO, NULL);
		if (rc)
			return (rc);
	} else {
		rc = security_fs_use(vfc_name, &behavior, &sid);
		if (rc)
			return (rc);
	}

	rc = avc_has_perm(task->sid, sid, SECCLASS_FILESYSTEM,
	    FILESYSTEM__MOUNT, NULL);

	return (rc);
}

static int
sebsd_check_mount_stat(struct ucred *cred, struct mount *mp,
    struct label *mntlabel)
{

	return (mount_has_perm(cred, mp, FILESYSTEM__GETATTR, NULL));
}

static int
sebsd_check_remount(struct ucred *cred, struct mount *mp,
    struct label *mntlabel, struct label *mount_arg_label)
{

	/* Cannot change labels on filesystems. */
	if (mount_arg_label) {
		struct mount_security_struct *mla = SLOT(mntlabel);
		struct mount_security_struct *mlb = SLOT(mount_arg_label);
		if (mla->sid != mlb->sid)
			return (EINVAL);
	}
	return (mount_has_perm(cred, mp, FILESYSTEM__REMOUNT, NULL));
}

static int
sebsd_check_umount(struct ucred *cred, struct mount *mp,
    struct label *mntlabel)
{

	return (mount_has_perm(cred, mp, FILESYSTEM__UNMOUNT, NULL));
}

static int
sebsd_check_pipe_ioctl(struct ucred *cred, struct pipepair *pp,
    struct label *pipelabel, unsigned long cmd, void /* caddr_t */ *data)
{

	return (pipe_has_perm(cred, pp, FIFO_FILE__IOCTL));
}

#if 0
static int
sebsd_check_pipe_poll(struct ucred *cred, struct pipepair *pp,
    struct label *pipelabel)
{

	return (pipe_has_perm(cred, pp, FIFO_FILE__POLL));
}
#endif

static int
sebsd_check_pipe_read(struct ucred *cred, struct pipepair *pp,
    struct label *pipelabel)
{

	return (pipe_has_perm(cred, pp, FIFO_FILE__READ));
}

static int
sebsd_check_pipe_relabel(struct ucred *cred, struct pipepair *pp,
    struct label *pipelabel, struct label *newlabel)
{
	struct task_security_struct *task;
	struct vnode_security_struct *file;
	struct vnode_security_struct *newfile;
	int rc;

	task = SLOT(cred->cr_label);
	file = SLOT(pipelabel);
	newfile = SLOT(newlabel);

	rc = avc_has_perm(task->sid, file->sid, file->sclass,
	    FIFO_FILE__RELABELFROM, NULL);
	if (rc)
		return (rc);

	rc = avc_has_perm(task->sid, newfile->sid, file->sclass,
	    FIFO_FILE__RELABELTO, NULL);

#if 0
	/* TBD: SELinux also check filesystem associate permission: */
	        return (avc_has_perm(newsid,
	                             sbsec->sid,
	                             SECCLASS_FILESYSTEM,
	                             FILESYSTEM__ASSOCIATE,
	                             &ad));
#endif
	return (rc);
}

static int
sebsd_check_pipe_stat(struct ucred *cred, struct pipepair *pp,
    struct label *pipelabel)
{

	return (pipe_has_perm(cred, pp, FIFO_FILE__GETATTR));
}

static int
sebsd_check_pipe_write(struct ucred *cred, struct pipepair *pp,
    struct label *pipelabel)
{

	return (pipe_has_perm(cred, pp, FIFO_FILE__WRITE));
}

static int
sebsd_check_proc_debug(struct ucred *cred, struct proc *proc)
{

	return (cred_has_perm(cred, proc, PROCESS__PTRACE));
}

static int
sebsd_check_proc_sched(struct ucred *cred, struct proc *proc)
{

	return (cred_has_perm(cred, proc, PROCESS__SETSCHED));
}

/* 
 * TBD: The SETGID and SETUID capabilities are currently used for
 * all functions in those families.
 */
static int
sebsd_check_proc_setgid(struct ucred *cred, gid_t gid)
{

        return (cred_has_capability(cred, CAPABILITY__SETGID));
}

static int
sebsd_check_proc_setregid(struct ucred *cred, gid_t rgid, gid_t egid)
{

	return (cred_has_capability(cred, CAPABILITY__SETGID));
}

static int
sebsd_check_proc_setresgid(struct ucred *cred, gid_t rgid, gid_t egid,
    gid_t sgid)
{

	return (cred_has_capability(cred, CAPABILITY__SETGID));
}

static int
sebsd_check_proc_setuid(struct ucred *cred, uid_t uid)
{

        return (cred_has_capability(cred, CAPABILITY__SETUID));
}

static int
sebsd_check_proc_setreuid(struct ucred *cred, uid_t ruid, uid_t euid)
{

        return (cred_has_capability(cred, CAPABILITY__SETUID));
}

static int
sebsd_check_proc_setresuid(struct ucred *cred, uid_t ruid, uid_t euid,
    uid_t suid)
{

        return (cred_has_capability(cred, CAPABILITY__SETUID));
}

static int
sebsd_check_proc_signal(struct ucred *cred, struct proc *proc, int signum)
{
	u_int32_t perm;

	perm = signal_to_av(signum);
	return (cred_has_perm(cred, proc, perm));
}

static int
sebsd_check_proc_wait(struct ucred *cred, struct proc *proc)
{
        u_int32_t perm, exit_status;

        exit_status = proc->p_xstat;    // (promote to 32 btis)
        exit_status &= 0177;

        perm = signal_to_av(exit_status);
        return (cred_has_perm(cred, proc, perm));
}

static void
sebsd_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vnodelabel, struct label *interpvnodelabel,
    struct image_params *imgp, struct label *execlabel)
{
	struct task_security_struct *otask, *ntask;
	struct vnode_security_struct *file;

	otask = SLOT(old->cr_label);
	ntask = SLOT(new->cr_label);
	if (interpvnodelabel != NULL)
		file = SLOT(interpvnodelabel);
	else
		file = SLOT(vnodelabel);

	/*
	 * Should have already checked all the permissions
	 * Should have no races with file/process labels
	 * So just make the transition.
	 */
	ntask->osid = otask->sid;
	if (execlabel == NULL)
		(void)security_transition_sid(otask->sid, file->sid,
		    SECCLASS_PROCESS, &ntask->sid);
	else
		ntask->sid = ((struct task_security_struct *)
		    SLOT(execlabel))->sid;

	if (otask->sid != ntask->sid) {
		/*
		 * TBD: Need to flush any open files that are now
		 * unauthorized.  Likewise, SELinux forced a wait
		 * permission check if the parent was waiting.
		 */
	}
}

static int
sebsd_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vnodelabel, struct label *interpvnodelabel,
    struct image_params *imgp, struct label *execlabel)
{
	struct task_security_struct *task;
	struct vnode_security_struct *file;
	u_int32_t newsid;

	task = SLOT(old->cr_label);
	if (interpvnodelabel != NULL)
		file = SLOT(interpvnodelabel);
	else
		file = SLOT(vnodelabel);

	/*
	 * Should have already checked all the permissions, so just see if
	 * the SIDS are going to match.
	 */
	if (execlabel == NULL)
		(void)security_transition_sid(task->sid, file->sid,
		    SECCLASS_PROCESS, &newsid);
	else
		newsid = ((struct task_security_struct *)
		    SLOT(execlabel))->sid;

	return (newsid != task->sid);
}

static int
sebsd_internalize_sid(u_int32_t *sidp, char *element_name,
    char *element_data, int *claimed)
{
	char context[128];  /* TBD: contexts aren't fixed size */
	size_t context_len;

	if (strcmp("sebsd", element_name) != 0)
		return (0);
	(*claimed)++;

	if (strlcpy(context, element_data, sizeof(context)) >=
	    sizeof(context))
		return (ENAMETOOLONG);
	context_len = strlen(context)+1;

	return (security_context_to_sid(context, context_len, sidp));
}

static int
sebsd_internalize_cred_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct task_security_struct *tsec;

	tsec = SLOT(label);
	return (sebsd_internalize_sid(&tsec->sid, element_name, element_data,
	    claimed));
}

static int
sebsd_internalize_network_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct network_security_struct *nsec;

	nsec = SLOT(label);
	return (sebsd_internalize_sid(&nsec->sid, element_name, element_data,
	    claimed));
}

static int
sebsd_internalize_vnode_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct vnode_security_struct *vsec;

	vsec = SLOT(label);
	return (sebsd_internalize_sid(&vsec->sid, element_name, element_data,
	    claimed));
}

static int
sebsd_internalize_mount_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct mount_security_struct *vsec;

	vsec = SLOT(label);
	return (sebsd_internalize_sid(&vsec->sid, element_name, element_data,
	    claimed));
}

static void
sebsd_relabel_pipe(struct ucred *cred, struct pipepair *pipe,
    struct label *pipelabel, struct label *newlabel)
{
	struct vnode_security_struct *source, *dest;

	source = SLOT(newlabel);
	dest = SLOT(pipelabel);

	/* XXXRW: Should be KASSERT's? */
	if (!source) {
		printf("sebsd_relabel_pipe:: source is NULL!\n");
		return;
	}
	if (!dest) {
		printf("sebsd_relabel_pipe:: dest is NULL!\n");
		return;
	}

	dest->sid = source->sid;
}

static void
sebsd_relabel_socket(struct ucred *cred, struct socket *so, 
    struct label *oldlabel, struct label *newlabel)
{

	copy_network_label(oldlabel, newlabel);
}

static void
sebsd_relabel_vnode(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, struct label *label)
{
	struct vnode_security_struct *source, *dest;

	source = SLOT(label);
	dest = SLOT(vnodelabel);

	/* XXXRW: Should be KASSERT's? */
	if (!source) {
		printf("sebsd_relabel_vnode:: source is NULL!\n");
		return;
	}
	if (!dest) {
		printf("sebsd_relabel_vnode:: dest is NULL!\n");
		return;
	}

	dest->sid = source->sid;
}

static int
sebsd_setlabel_vnode_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vlabel, struct label *intlabel)
{
	struct vnode_security_struct *newlabel;
	char *context;
	u_int32_t context_len;
	int error;

	newlabel = SLOT(intlabel);

	error = security_sid_to_context(newlabel->sid, &context, &context_len);
	if (error)
		return (error);

	error = vn_extattr_set(vp, IO_NODELOCKED,
	    SEBSD_MAC_EXTATTR_NAMESPACE, SEBSD_MAC_EXTATTR_NAME,
	    context_len, context, curthread);
	security_free_context(context);
	return (error);
}

#if 0
static void
sebsd_set_socket_peer_from_mbuf(struct mbuf *m, struct label *mlabel,
    struct socket *so, struct label *sopeerlabel)
{

	copy_network_label(mlabel, sopeerlabel);
}
#endif

static void
sebsd_set_socket_peer_from_socket(struct socket *olds, struct label *oldslabel,
    struct socket *news, struct label *newsockpeerlabel)
{

	copy_network_label(oldslabel, newsockpeerlabel);
}

static int
sebsd_check_vnode_access(struct ucred *cred, struct vnode *vp,
    struct label *label, int acc_mode)
{

	/* existence check (F_OK) */
	if (acc_mode == 0)
		return (0);

	return (vnode_has_perm(cred, vp,
	    file_mask_to_av(vp->v_type, acc_mode)));
}

static int
sebsd_check_vnode_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{

	/* MAY_EXEC ~= DIR__SEARCH */
	return (vnode_has_perm(cred, dvp, DIR__SEARCH));
}

static int
sebsd_check_vnode_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{

	/* TBD: Incomplete, SELinux also check capability(CAP_SYS_CHROOT)) */
	/* MAY_EXEC ~= DIR__SEARCH */
	return (vnode_has_perm(cred, dvp, DIR__SEARCH));
}

static int
sebsd_check_vnode_create(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp, struct vattr *vap)
{
	struct task_security_struct *task;
	struct vnode_security_struct *dir;
	struct mount_security_struct *sbsec;
	u_int16_t tclass;
	u_int32_t newsid;
	struct avc_audit_data ad;
	int rc;

	task = SLOT(cred->cr_label);
	dir = SLOT(dlabel);

	tclass = vnode_type_to_security_class(vap->va_type);

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = dvp;

	rc = avc_has_perm(task->sid, dir->sid, SECCLASS_DIR,
	    DIR__ADD_NAME | DIR__SEARCH, &ad);
	if (rc)
		return (rc);

	rc = security_transition_sid(task->sid, dir->sid, tclass, &newsid);
	if (rc)
		return (rc);

	rc = avc_has_perm(task->sid, newsid, tclass, FILE__CREATE, &ad);
	if (rc)
		return (rc);

	if (dvp->v_mount) {
		/*
		 * XXX: mpo_check_vnode_create should probably pass the
		 * mntlabel.
		 */
		sbsec = SLOT(dvp->v_mount->mnt_mntlabel);
		rc = avc_has_perm(newsid, sbsec->sid,
		    SECCLASS_FILESYSTEM, FILESYSTEM__ASSOCIATE, &ad);
		if (rc)
			return (rc);
	}

	return (0);
}

static int
sebsd_check_vnode_delete(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	struct task_security_struct *task;
	struct vnode_security_struct *dir, *file;
	struct avc_audit_data ad;
	u_int32_t av;
	int rc;

	task = SLOT(cred->cr_label);
	file = SLOT(label);
	dir  = SLOT(dlabel);

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;

	rc = avc_has_perm(task->sid, dir->sid, SECCLASS_DIR,
	    DIR__SEARCH | DIR__REMOVE_NAME, &ad);
	if (rc)
		return (rc);

	if (file->sclass == SECCLASS_DIR)
		av = DIR__RMDIR;
	else
		av = FILE__UNLINK;

	rc = avc_has_perm(task->sid, file->sid, file->sclass, av, &ad);

	return (rc);
}

static int
sebsd_check_vnode_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *label, acl_type_t type)
{

	return (vnode_has_perm(cred, vp, FILE__SETATTR));
}

static int
sebsd_check_vnode_exec(struct ucred *cred, struct vnode *vp,
    struct label *label, struct image_params *imgp, struct label *execlabel)
{
	struct task_security_struct *task;
	struct vnode_security_struct *file;
	u_int32_t newsid;
	struct avc_audit_data ad;
	int rc;

	task = SLOT(cred->cr_label);
	file = SLOT(label);
	if (execlabel == NULL) {
		rc = security_transition_sid(task->sid, file->sid,
		    SECCLASS_PROCESS, &newsid);
		if (rc)
			return (EACCES);
	} else
		newsid = ((struct task_security_struct *)
		    SLOT(execlabel))->sid;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;

	if (newsid == task->sid) {
		rc = avc_has_perm(task->sid, file->sid, SECCLASS_FILE,
		    FILE__EXECUTE_NO_TRANS, &ad);
		if (rc)
			return (EACCES);
	} else {
		/* Check permissions for the transition. */
		rc = avc_has_perm(task->sid, newsid, SECCLASS_PROCESS,
		    PROCESS__TRANSITION, &ad);
		if (rc)
			return (EACCES);
		rc = avc_has_perm(newsid, file->sid, SECCLASS_FILE,
		    FILE__ENTRYPOINT, &ad);
		if (rc)
			return (EACCES);

		/*
		 * TBD: Check ptrace permission between the parent and
		 * the new SID for this process if this process is
		 * being traced.
		 */

		/*
		 * TBD: Check share permission between the old and new
		 * SIDs of the process if the process will share
		 * state.
		 */
	}

	return (0);
}

static int
sebsd_check_vnode_getacl(struct ucred *cred, struct vnode *vp,
    struct label *label, acl_type_t type)
{

	return (vnode_has_perm(cred, vp, FILE__GETATTR));
}

static int
sebsd_check_vnode_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *label, int attrnamespace, const char *name, struct uio *uio)
{

	return (vnode_has_perm(cred, vp, FILE__GETATTR));
}

static int
sebsd_check_vnode_link(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	struct task_security_struct *task;
	struct vnode_security_struct *dir, *file;
	struct avc_audit_data ad;
	int rc;

	task = SLOT(cred->cr_label);
	file = SLOT(label);
	dir  = SLOT(dlabel);

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;

	rc = avc_has_perm(task->sid, dir->sid, SECCLASS_DIR,
	    DIR__SEARCH | DIR__ADD_NAME, &ad);
	if (rc)
		return (rc);

	rc = avc_has_perm(task->sid, file->sid, file->sclass,
	    FILE__LINK, &ad);

	return (0);
}

static int
sebsd_check_vnode_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp)
{

	/* TBD: DIR__READ as well? */
	return (vnode_has_perm(cred, dvp, DIR__SEARCH));
}

static int
sebsd_check_vnode_open(struct ucred *cred, struct vnode *vp,
    struct label *filelabel, int acc_mode)
{

	if (!acc_mode)
		return (0);

	return (vnode_has_perm(cred, vp, file_mask_to_av(vp->v_type,
	    acc_mode)));
}

#if 0
static int
sebsd_check_vnode_poll(struct ucred *cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{

	return (vnode_has_perm(cred, vp, FILE__POLL));
}
#endif

static int
sebsd_check_vnode_read(struct ucred *cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{

	return (vnode_has_perm(cred, vp, FILE__READ));
}

static int
sebsd_check_vnode_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{

	return (vnode_has_perm(cred, dvp, DIR__READ));
}

static int
sebsd_check_vnode_readlink(struct ucred *cred, struct vnode *vp,
    struct label *label)
{

	return (vnode_has_perm(cred, vp, FILE__READ));
}

static int
sebsd_check_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *oldlabel, struct label *newlabel)
{
	struct task_security_struct *task;
	struct mount_security_struct *sbsec;
	struct vnode_security_struct *old, *new;
	struct avc_audit_data ad;
	int rc;

	task = SLOT(cred->cr_label);
	old = SLOT(oldlabel);
	new = SLOT(newlabel);

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;

	if (old->sclass == 0) {
		printf("vnode_relabel:: ERROR, sid=%d, sclass=0, v_type=%d\n",
		       old->sid, vp->v_type);
		return (0);	/* TBD: debugging */
	}
	rc = avc_has_perm(task->sid, old->sid, old->sclass,
	    FILE__RELABELFROM, &ad);
	if (rc)
		return (rc);

	rc = avc_has_perm(task->sid, new->sid, old->sclass,
	    FILE__RELABELTO, &ad);
	if (rc)
		return (rc);

	if (vp->v_mount) {
		/*
		 * XXX: mpo_check_vnode_relabel should probably pass the
		 * mntlabel.
		 */
		sbsec = SLOT(vp->v_mount->mnt_mntlabel);
		rc = avc_has_perm(new->sid, sbsec->sid,
		    SECCLASS_FILESYSTEM, FILESYSTEM__ASSOCIATE, &ad);
		if (rc)
			return (rc);
	}

	return (0);
}

static int
sebsd_check_vnode_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	struct task_security_struct *task;
	struct vnode_security_struct *old_dir, *old_file;
	struct avc_audit_data ad;
	int rc;

	task = SLOT(cred->cr_label);
	old_dir = SLOT(dlabel);
	old_file = SLOT(label);

	AVC_AUDIT_DATA_INIT(&ad, FS);

	rc = avc_has_perm(task->sid, old_dir->sid, SECCLASS_DIR,
	    DIR__REMOVE_NAME | DIR__SEARCH, &ad);
	if (rc)
		return (rc);
	if (old_file->sclass == 0) {
		printf("vnode_rename_from:: ERROR, sid=%d, sclass=0, "
		    "v_type=%d\n", old_file->sid, vp->v_type);
		return (0);	/* TBD: debugging */
	}

	rc = avc_has_perm(task->sid, old_file->sid,
	    old_file->sclass, FILE__RENAME, &ad);
	if (rc)
		return (rc);

	return (0);
}

static int
sebsd_check_vnode_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label, int samedir,
    struct componentname *cnp)
{
	struct task_security_struct *task;
	struct vnode_security_struct *new_dir, *new_file;
	struct avc_audit_data ad;
	u_int32_t av;
	int rc;

	task = SLOT(cred->cr_label);
	new_dir = SLOT(dlabel);

#ifdef notdef
	/*
	 * We don't have the right information available to make this
	 * test. TBD - find a way!
	 */
	if (vp->v_type == VDIR && !samedir) {
		rc = avc_has_perm(task->sid, old_file->sid,
		    old_file->sclass, DIR__REPARENT, NULL);
		if (rc)
			return (rc);
	}
#endif

	av = DIR__ADD_NAME | DIR__SEARCH;
	if (vp)
		av |= DIR__REMOVE_NAME;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;

	rc = avc_has_perm(task->sid, new_dir->sid, SECCLASS_DIR, av, NULL);
	if (rc)
		return (rc);

	if (vp) {
		new_file = SLOT(label);
		if (new_file->sclass == 0) {
			printf("vnode_relabel_to:: ERROR, sid=%d, sclass=0, "
			       "v_type=%d\n", new_file->sid, vp->v_type);
			return (0);	/* TBD: debugging */
		}
		if (vp->v_type == VDIR)
			rc = avc_has_perm(task->sid, new_file->sid,
			    new_file->sclass, DIR__RMDIR, NULL);
		else
			rc = avc_has_perm(task->sid, new_file->sid,
			    new_file->sclass, FILE__UNLINK, NULL);
		if (rc)
			return (rc);
	}

	return (0);
}

static int
sebsd_check_vnode_revoke(struct ucred *cred, struct vnode *vp,
    struct label *label)
{

	/* TBD: Not Implemented */
	return (0);
}

static int
sebsd_check_vnode_setacl(struct ucred *cred, struct vnode *vp,
    struct label *label, acl_type_t type, struct acl *acl)
{

	return (vnode_has_perm(cred, vp, FILE__SETATTR));
}

static int
sebsd_check_vnode_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *label, int attrnamespace, const char *name, struct uio *uio)
{

	return (vnode_has_perm(cred, vp, FILE__SETATTR));
}

static int
sebsd_check_vnode_setflags(struct ucred *cred, struct vnode *vp,
    struct label *label, u_long flags)
{

	return (vnode_has_perm(cred, vp, FILE__SETATTR));
}

static int
sebsd_check_vnode_setmode(struct ucred *cred, struct vnode *vp,
    struct label *label, mode_t mode)
{

	return (vnode_has_perm(cred, vp, FILE__SETATTR));
}

static int
sebsd_check_vnode_setowner(struct ucred *cred, struct vnode *vp,
    struct label *label, uid_t uid, gid_t gid)
{

	return (vnode_has_perm(cred, vp, FILE__SETATTR));
}

static int
sebsd_check_vnode_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *label, struct timespec atime, struct timespec mtime)
{

	return (vnode_has_perm(cred, vp, FILE__SETATTR));
}

static int
sebsd_check_vnode_stat(struct ucred *cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vnodelabel)
{

	return (vnode_has_perm(cred, vp, FILE__GETATTR));
}

static int
sebsd_check_system_acct(struct ucred *cred, struct vnode *c,
    struct label *vl)
{

	return (cred_has_capability(cred, CAPABILITY__SYS_PACCT));
}

/*
 * TBD: LSM/SELinux doesn't have a nfsd hook
 */
static int
sebsd_check_system_nfsd(struct ucred *cred)
{

	return (0);
}

static int
sebsd_check_system_reboot(struct ucred *cred, int how)
{

        return (cred_has_capability(cred, CAPABILITY__SYS_BOOT));
}

static int
sebsd_check_system_settime(struct ucred *cred)
{

        return (cred_has_capability(cred, CAPABILITY__SYS_TIME));
}

static int
sebsd_check_system_swapon(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel)
{

	return (vnode_has_perm(cred, vp, FILE__SWAPON));
}

static int
sebsd_check_system_swapoff(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel)
{

	return (vnode_has_perm(cred, vp, FILE__SWAPON));
}

/*
 * TBD: Sysctl access control is not currently implemented
 */
static int
sebsd_check_system_sysctl(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req)
{

	return (0);
}

static int
sebsd_check_vnode_write(struct ucred *cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{

	return (vnode_has_perm(cred, vp, FILE__WRITE));
}

/*
 * Also registered for MAC_CHECK_VNODE_MPROTECT.
 */
static int
sebsd_check_vnode_mmap(struct ucred *cred, struct vnode *vp,
    struct label *label, int prot, int flags)
{
	u_int32_t av;

	/*
	 * TBD: Incomplete?
	 * Write access only matters if the mapping is shared.
	 */
	if (vp) {
		av = FILE__READ;

		if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
			av |= FILE__WRITE;

		if (prot & PROT_EXEC)
			av |= FILE__EXECUTE;

		return (vnode_has_perm(cred, vp, av));
	}
	return (0);
}

static int
sebsd_externalize_sid(u_int32_t sid, char *element_name,
    struct sbuf *sb, int *claimed)
{
	char *context;
	u_int32_t context_len;
	int error;

	if (strcmp("sebsd", element_name) != 0)
		return (0);

	(*claimed)++;

	error = security_sid_to_context(sid, &context, &context_len);
	if (error)
		return (error);

	if (sbuf_cat(sb, context) == -1)
		error = EINVAL;
	security_free_context(context);
	return (error);
}

static int
sebsd_externalize_cred_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct task_security_struct *task;

	task = SLOT(label);
	return (sebsd_externalize_sid(task->sid, element_name, sb, claimed));
}

static int
sebsd_externalize_vnode_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct vnode_security_struct *vsec;

	vsec = SLOT(label);
	return (sebsd_externalize_sid(vsec->sid, element_name, sb, claimed));
}

static int
sebsd_externalize_mount_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct mount_security_struct *vsec;

	vsec = SLOT(label);
	return (sebsd_externalize_sid(vsec->sid, element_name, sb, claimed));
}

static int
sebsd_externalize_network_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct network_security_struct *nsec;

	nsec = SLOT(label);
	return (sebsd_externalize_sid(nsec->sid, element_name, sb, claimed));
}

static void
sebsd_copy_vnode_label(struct label *src, struct label *dest)
{

	*(struct vnode_security_struct *)SLOT(dest) =
	    *(struct vnode_security_struct *)SLOT(src);
}

static void
sebsd_copy_mount_label(struct label *src, struct label *dest)
{

	*(struct mount_security_struct *)SLOT(dest) =
	    *(struct mount_security_struct *)SLOT(src);
}

#if 0
static int
sebsd_check_file_create(struct ucred *cred)
{
	struct task_security_struct *tsec;

	tsec = SLOT(cred->cr_label);
	return (avc_has_perm(tsec->sid, tsec->sid, SECCLASS_FD,
	    FD__CREATE, NULL));
}
#endif

static int
sebsd_check_file_ioctl(struct ucred *cred, struct file *fp,
    struct label *fplabel, u_long com)
{
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;
	int error;

	tsec = SLOT(cred->cr_label);
	fsec = SLOT(fplabel);

	error = avc_has_perm(tsec->sid, fsec->sid, SECCLASS_FD,
	    FD__USE, NULL);
	if (error)
		return (error);
	if (fp->f_type != DTYPE_VNODE)
		return (0);

	return (vnode_has_perm(cred, fp->f_vnode, FILE__IOCTL));
}

/*
 * Simplify all other fd permissions to just "use" for now.  The ones we
 * implement in SEBSD roughly correlate to the SELinux FD__USE permissions,
 * and not the fine-grained FLASK permissions.
 */
static int
sebsd_check_file_get_flags(struct ucred *cred, struct file *fp,
    struct label *fplabel, u_int flags)
{
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	tsec = SLOT(cred->cr_label);
	fsec = SLOT(fplabel);
	return (avc_has_perm(tsec->sid, fsec->sid, SECCLASS_FD,
	    FD__USE, NULL));
}

static int
sebsd_check_file_get_ofileflags(struct ucred *cred, struct file *fp,
    struct label *fplabel, char flags)
{
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	tsec = SLOT(cred->cr_label);
	fsec = SLOT(fplabel);
	return (avc_has_perm(tsec->sid, fsec->sid, SECCLASS_FD,
	    FD__USE, NULL));
}

static int
sebsd_check_file_change_flags(struct ucred *cred, struct file *fp,
    struct label *fplabel, u_int oldflags, u_int newflags)
{
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	tsec = SLOT(cred->cr_label);
	fsec = SLOT(fplabel);
	return (avc_has_perm(tsec->sid, fsec->sid, SECCLASS_FD,
	    FD__USE, NULL));
}

static int
sebsd_check_file_change_ofileflags(struct ucred *cred, struct file *fp,
    struct label *fplabel, char oldflags, char newflags)
{
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	tsec = SLOT(cred->cr_label);
	fsec = SLOT(fplabel);
	return (avc_has_perm(tsec->sid, fsec->sid, SECCLASS_FD,
	    FD__USE, NULL));
}

static int
sebsd_check_file_get_offset(struct ucred *cred, struct file *fp,
    struct label *fplabel)
{
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	tsec = SLOT(cred->cr_label);
	fsec = SLOT(fplabel);
	return (avc_has_perm(tsec->sid, fsec->sid, SECCLASS_FD,
	    FD__USE, NULL));
}

static int
sebsd_check_file_change_offset(struct ucred *cred, struct file *fp,
    struct label *fplabel)
{
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	tsec = SLOT(cred->cr_label);
	fsec = SLOT(fplabel);
	return (avc_has_perm(tsec->sid, fsec->sid, SECCLASS_FD,
	    FD__USE, NULL));
}

static int
ipc_has_perm(struct ucred *cred, struct label *label, u_int32_t perm)
{
	struct task_security_struct *task;
	struct ipc_security_struct *ipcsec;

	task = SLOT(cred->cr_label);
	ipcsec = SLOT(label);

	/*
	 * TBD: No audit information yet
	 */

	return (avc_has_perm(task->sid, ipcsec->sid, ipcsec->sclass,
	    perm, NULL));
}

static int
sebsd_check_sysv_msgrcv(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{

	return (ipc_has_perm(cred, msglabel, MSG__RECEIVE));
}

#if 0
static int
sebsd_check_sysv_msgrmid(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{

 	return (ipc_has_perm(cred, msglabel, MSG__DESTROY));
}
#endif

static int
sebsd_check_sysv_msqget(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{

	return (ipc_has_perm(cred, msqklabel, MSGQ__ASSOCIATE));
}

static int
sebsd_check_sysv_msqsnd(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{

	/* Can this process write to the queue? */
	return (ipc_has_perm(cred, msqklabel, MSGQ__WRITE));
}

static int
sebsd_check_sysv_msgmsq(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	int rc;
	struct task_security_struct *task;
	struct ipc_security_struct *msgsec;
	struct ipc_security_struct *msqsec;

	task = SLOT(cred->cr_label);
	msgsec = SLOT(msglabel);
	msqsec = SLOT(msqklabel);

	/*
	 * TBD: No audit information yet
	 */

	/* Can this process send the message */
	rc = avc_has_perm(task->sid, msgsec->sid, msgsec->sclass,
	    MSG__SEND, NULL);
	if (rc)
		return (rc);

	/* Can the message be put in the message queue? */
	return (avc_has_perm(msgsec->sid, msqsec->sid, msqsec->sclass,
	    MSGQ__ENQUEUE, NULL));
}

static int
sebsd_check_sysv_msqrcv(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{

	return (ipc_has_perm(cred, msqklabel, MSGQ__READ));
}

static int
sebsd_check_sysv_msqctl(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel, int cmd)
{
	u_int32_t perm;

	switch(cmd) {
	case IPC_RMID:
		perm = MSGQ__DESTROY;
		break;
	case IPC_SET:
		perm = MSGQ__SETATTR;
		break;
	case IPC_STAT:
		perm = MSGQ__GETATTR | MSGQ__ASSOCIATE;
		break;
	default:
		return (EACCES);
	}

	/*
	 * TBD: No audit information yet
	 */
	return (ipc_has_perm(cred, msqklabel, perm));
}

static int
sebsd_check_sysv_semctl(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel, int cmd)
{
	u_int32_t perm;

	switch(cmd) {
	case GETPID:
	case GETNCNT:
	case GETZCNT:
		perm = SEM__GETATTR;
		break;
	case GETVAL:
	case GETALL:
		perm = SEM__READ;
		break;
	case SETVAL:
	case SETALL:
		perm = SEM__WRITE;
		break;
	case IPC_RMID:
		perm = SEM__DESTROY;
		break;
	case IPC_SET:
		perm = SEM__SETATTR;
		break;
	case IPC_STAT:
		perm = SEM__GETATTR | SEM__ASSOCIATE;
		break;
	default:
		return (EACCES);
	}

	/*
	 * TBD: No audit information yet
	 */
	return (ipc_has_perm(cred, semaklabel, perm));
}

static int
sebsd_check_sysv_semget(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel)
{

	return (ipc_has_perm(cred, semaklabel, SEM__ASSOCIATE));
}

static int
sebsd_check_sysv_semop(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel, size_t accesstype)
{
	u_int32_t perm;
	perm = 0UL;

	if (accesstype & SEM_R)
		perm = SEM__READ;
	if (accesstype & SEM_A)
		perm = SEM__READ | SEM__WRITE;

	return (ipc_has_perm(cred, semaklabel, perm));
}

static int
sebsd_check_sysv_shmat(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int shmflg)
{
	u_int32_t perm;

	if (shmflg & SHM_RDONLY)
		perm = SHM__READ;
	else
		perm = SHM__READ | SHM__WRITE;

	return (ipc_has_perm(cred, shmseglabel, perm));
}

static int
sebsd_check_sysv_shmctl(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int cmd)
{
	u_int32_t perm;

	switch(cmd) {
	case IPC_RMID:
		perm = SHM__DESTROY;
		break;
	case IPC_SET:
		perm = SHM__SETATTR;
		break;
	case IPC_STAT:
	case SHM_STAT:
		perm = SHM__GETATTR | SHM__ASSOCIATE;
		break;
	default:
		return (EACCES);
	}

	return (ipc_has_perm(cred, shmseglabel, perm));

}

static int
sebsd_check_sysv_shmget(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int shmflg)
{

	return (ipc_has_perm(cred, shmseglabel, SHM__ASSOCIATE));
}

#ifdef MAC_NO_LOONGER
/*
 * POSIX does not allow sem_close() to fail for reasons other than an invalid
 * semaphore pointer, and close on exit is unconditional.  As such, the MAC
 * Framework does not allow access control on sem_close().
 */
static int
sebsd_check_posix_sem_close(struct ucred *cred, struct ksem *ksemptr,
    struct label *ks_label)
{

	return (ipc_has_perm(cred, ks_label, SEM__DISASSOCIATE));
}
#endif

static int
sebsd_check_posix_sem_destroy(struct ucred *cred, struct ksem *ksemptr,
    struct label *ks_label)
{

	return (ipc_has_perm(cred, ks_label, SEM__DESTROY));
}

static int
sebsd_check_posix_sem_getvalue(struct ucred *cred, struct ksem *ksemptr,
    struct label *ks_label)
{

	return (ipc_has_perm(cred, ks_label, SEM__READ));
}

static int
sebsd_check_posix_sem_open(struct ucred *cred, struct ksem *ksemptr,
    struct label *ks_label)
{

	return (ipc_has_perm(cred, ks_label, SEM__ASSOCIATE));
}

static int
sebsd_check_posix_sem_post(struct ucred *cred, struct ksem *ksemptr,
    struct label *ks_label)
{

	return (ipc_has_perm(cred, ks_label, SEM__WRITE));
}

static int
sebsd_check_posix_sem_unlink(struct ucred *cred, struct ksem *ksemptr,
    struct label *ks_label)
{

	return (ipc_has_perm(cred, ks_label, SEM__DESTROY));
}

static int
sebsd_check_posix_sem_wait(struct ucred *cred, struct ksem *ksemptr,
    struct label *ks_label)
{

	return (ipc_has_perm(cred, ks_label, SEM__WRITE));
}

static struct mac_policy_ops sebsd_ops = {
	/* Init Labels */
	.mpo_init = sebsd_init,
	.mpo_init_bpfdesc_label = sebsd_init_network_label,
	.mpo_init_cred_label = sebsd_init_cred_label,
	.mpo_init_devfsdirent_label = sebsd_init_vnode_label,
	.mpo_init_file_label = sebsd_init_file_label,
	.mpo_init_ifnet_label = sebsd_init_network_label,
	.mpo_init_inpcb_label = sebsd_init_network_label_waitcheck,
	.mpo_init_sysv_msgmsg_label = sebsd_init_sysv_label,
	.mpo_init_sysv_msgqueue_label = sebsd_init_sysv_label,
	.mpo_init_sysv_sem_label = sebsd_init_sysv_label,
	.mpo_init_sysv_shm_label = sebsd_init_sysv_label,
	//.mpo_init_ipq_label = sebsd_init_network_label_waitcheck,
	//.mpo_init_mbuf_label = sebsd_init_network_label_waitcheck,
	.mpo_init_mount_label = sebsd_init_mount_label,
	.mpo_init_mount_fs_label = sebsd_init_mount_fs_label,
	.mpo_init_pipe_label = sebsd_init_vnode_label,
	.mpo_init_posix_sem_label = sebsd_init_sysv_label,
	.mpo_init_socket_label = sebsd_init_network_label_waitcheck,
	.mpo_init_socket_peer_label = sebsd_init_network_label_waitcheck,
	.mpo_init_vnode_label = sebsd_init_vnode_label,

	/* Destroy Labels */
	.mpo_destroy = sebsd_destroy,
	.mpo_destroy_bpfdesc_label = sebsd_destroy_label,
	.mpo_destroy_cred_label = sebsd_destroy_label,
	.mpo_destroy_devfsdirent_label = sebsd_destroy_label,
	.mpo_destroy_ifnet_label = sebsd_destroy_label,
	.mpo_destroy_inpcb_label = sebsd_destroy_label,
	.mpo_destroy_sysv_msgmsg_label = sebsd_destroy_label,
	.mpo_destroy_sysv_msgqueue_label = sebsd_destroy_label,
	.mpo_destroy_sysv_sem_label = sebsd_destroy_label,
	.mpo_destroy_sysv_shm_label = sebsd_destroy_label,
	//.mpo_destroy_ipq_label = sebsd_destroy_label,
	//.mpo_destroy_mbuf_label = sebsd_destroy_label,
	.mpo_destroy_file_label = sebsd_destroy_label,
	.mpo_destroy_mount_label = sebsd_destroy_label,
	.mpo_destroy_mount_fs_label = sebsd_destroy_label,
	.mpo_destroy_pipe_label = sebsd_destroy_label,
	.mpo_destroy_posix_sem_label = sebsd_destroy_label,
	.mpo_destroy_socket_label = sebsd_destroy_label,
	.mpo_destroy_socket_peer_label = sebsd_destroy_label,
	.mpo_destroy_vnode_label = sebsd_destroy_label,

	/* Copy labels */
	.mpo_copy_ifnet_label = copy_network_label,
	//.mpo_copy_mbuf_label = copy_network_label,
	.mpo_copy_pipe_label = sebsd_copy_vnode_label,
	.mpo_copy_socket_label = copy_network_label,
	.mpo_copy_vnode_label = sebsd_copy_vnode_label,
	.mpo_copy_mount_label = sebsd_copy_mount_label,

	/* In/Out */
	.mpo_externalize_cred_label = sebsd_externalize_cred_label,
	.mpo_externalize_ifnet_label = sebsd_externalize_network_label,
	.mpo_externalize_pipe_label = sebsd_externalize_vnode_label,
	.mpo_externalize_socket_label = sebsd_externalize_network_label,
	.mpo_externalize_socket_peer_label = sebsd_externalize_network_label,
	.mpo_externalize_vnode_label = sebsd_externalize_vnode_label,
	.mpo_externalize_mount_label = sebsd_externalize_mount_label,
	.mpo_internalize_cred_label = sebsd_internalize_cred_label,
	.mpo_internalize_ifnet_label = sebsd_internalize_network_label,
	.mpo_internalize_pipe_label = sebsd_internalize_vnode_label,
	.mpo_internalize_socket_label = sebsd_internalize_network_label,
	.mpo_internalize_vnode_label = sebsd_internalize_vnode_label,
	.mpo_internalize_mount_label = sebsd_internalize_mount_label,

	/* Create Labels */
	.mpo_copy_cred_label = sebsd_copy_cred_label,
	.mpo_create_bpfdesc = sebsd_create_bpfdesc,
	//.mpo_create_datagram_from_ipq = sebsd_create_datagram_from_ipq,
	.mpo_create_devfs_device = sebsd_create_devfs_device,
	.mpo_create_devfs_directory = sebsd_create_devfs_directory,
	.mpo_create_devfs_symlink = sebsd_create_devfs_symlink,
	.mpo_create_file = sebsd_create_file,
	//.mpo_create_fragment = sebsd_create_fragment,
	.mpo_create_ifnet = sebsd_create_ifnet,
	.mpo_create_inpcb_from_socket = sebsd_create_inpcb_from_socket,
	//.mpo_create_ipq = sebsd_create_ipq,
	//.mpo_create_mbuf_from_bpfdesc = sebsd_create_mbuf_from_bpfdesc,
	//.mpo_create_mbuf_from_ifnet = sebsd_create_mbuf_from_ifnet,
	//.mpo_create_mbuf_from_inpcb = sebsd_create_mbuf_from_inpcb,
	//.mpo_create_mbuf_multicast_encap = sebsd_create_mbuf_multicast_encap,
	//.mpo_create_mbuf_from_socket = sebsd_create_mbuf_from_socket,
	//.mpo_create_mbuf_linklayer = sebsd_create_mbuf_linklayer,
	//.mpo_create_mbuf_netlayer = sebsd_create_mbuf_netlayer,
	.mpo_create_mount = sebsd_create_mount,
	.mpo_create_pipe = sebsd_create_pipe,
	.mpo_create_posix_sem = sebsd_create_posix_sem,
	.mpo_create_proc0 = sebsd_create_kernel_proc,
	.mpo_create_proc1 = sebsd_create_kernel_proc,
	.mpo_create_socket = sebsd_create_socket,
	.mpo_create_socket_from_socket = sebsd_create_socket_from_socket,
	.mpo_create_sysv_msgmsg = sebsd_create_sysv_msgmsg,
	.mpo_create_sysv_msgqueue = sebsd_create_sysv_msgqueue,
	.mpo_create_sysv_sem = sebsd_create_sysv_sem,
	.mpo_create_sysv_shm = sebsd_create_sysv_shm,
	.mpo_create_vnode_extattr = sebsd_create_vnode_extattr,
	.mpo_update_devfsdirent = sebsd_update_devfsdirent,
	//.mpo_update_ipq = sebsd_update_ipq,
	.mpo_inpcb_sosetlabel = sebsd_inpcb_sosetlabel,
	.mpo_associate_vnode_devfs =  sebsd_associate_vnode_devfs,
	.mpo_associate_vnode_singlelabel =  sebsd_associate_vnode_singlelabel,
	.mpo_associate_vnode_extattr =  sebsd_associate_vnode_extattr,

	/* Check Labels */
	.mpo_check_cap = sebsd_check_cap,
	.mpo_check_cred_relabel = sebsd_check_cred_relabel,
	/* .mpo_check_file_create = sebsd_check_file_create, */
	.mpo_check_file_ioctl = sebsd_check_file_ioctl,

	/*
	.mpo_check_file_dup
	.mpo_check_file_inherit
	.mpo_check_file_receive
	*/
	.mpo_check_file_get_flags = sebsd_check_file_get_flags,
	.mpo_check_file_get_ofileflags = sebsd_check_file_get_ofileflags,
	.mpo_check_file_get_offset = sebsd_check_file_get_offset,
	.mpo_check_file_change_flags = sebsd_check_file_change_flags,
	.mpo_check_file_change_ofileflags = sebsd_check_file_change_ofileflags,
	.mpo_check_file_change_offset = sebsd_check_file_change_offset,
	.mpo_check_mount = sebsd_check_mount,
	.mpo_check_umount = sebsd_check_umount,
	.mpo_check_remount = sebsd_check_remount,
	.mpo_check_sysv_msgmsq = sebsd_check_sysv_msgmsq,
	.mpo_check_sysv_msgrcv = sebsd_check_sysv_msgrcv,
	/* .mpo_check_sysv_msgrmid = sebsd_check_sysv_msgrmid, */
	.mpo_check_sysv_msqget = sebsd_check_sysv_msqget,
	.mpo_check_sysv_msqsnd = sebsd_check_sysv_msqsnd,
	.mpo_check_sysv_msqrcv = sebsd_check_sysv_msqrcv,
	.mpo_check_sysv_msqctl = sebsd_check_sysv_msqctl,
	.mpo_check_sysv_semctl = sebsd_check_sysv_semctl,
	.mpo_check_sysv_semget = sebsd_check_sysv_semget,
	.mpo_check_sysv_semop = sebsd_check_sysv_semop,
	.mpo_check_sysv_shmat = sebsd_check_sysv_shmat,
	.mpo_check_sysv_shmctl = sebsd_check_sysv_shmctl,
	/* .mpo_check_sysv_shmdt = sebsd_check_sysv_shmdt, */
	.mpo_check_sysv_shmget = sebsd_check_sysv_shmget,
	.mpo_check_mount_stat = sebsd_check_mount_stat,

	.mpo_check_pipe_ioctl = sebsd_check_pipe_ioctl,
	/* .mpo_check_pipe_poll = sebsd_check_pipe_poll, */
	.mpo_check_pipe_read = sebsd_check_pipe_read,
	.mpo_check_pipe_relabel = sebsd_check_pipe_relabel,
	.mpo_check_pipe_stat = sebsd_check_pipe_stat,
	.mpo_check_pipe_write = sebsd_check_pipe_write,

	.mpo_check_posix_sem_destroy = sebsd_check_posix_sem_destroy,
	.mpo_check_posix_sem_getvalue = sebsd_check_posix_sem_getvalue,
	.mpo_check_posix_sem_open = sebsd_check_posix_sem_open,
	.mpo_check_posix_sem_post = sebsd_check_posix_sem_post,
	.mpo_check_posix_sem_unlink = sebsd_check_posix_sem_unlink,
	.mpo_check_posix_sem_wait = sebsd_check_posix_sem_wait,

	.mpo_check_proc_debug = sebsd_check_proc_debug,
	.mpo_check_proc_sched = sebsd_check_proc_sched,
	.mpo_check_proc_setuid = sebsd_check_proc_setuid,
	.mpo_check_proc_seteuid = sebsd_check_proc_setuid,
	.mpo_check_proc_setgid = sebsd_check_proc_setgid,
	.mpo_check_proc_setegid = sebsd_check_proc_setgid,
	.mpo_check_proc_setreuid = sebsd_check_proc_setreuid,
	.mpo_check_proc_setregid = sebsd_check_proc_setregid,
	.mpo_check_proc_setresuid = sebsd_check_proc_setresuid,
	.mpo_check_proc_setresgid = sebsd_check_proc_setresgid,
	.mpo_check_proc_signal = sebsd_check_proc_signal,
	.mpo_check_proc_wait = sebsd_check_proc_wait,
	.mpo_check_system_acct = sebsd_check_system_acct,
	.mpo_check_system_nfsd = sebsd_check_system_nfsd,
	.mpo_check_system_reboot = sebsd_check_system_reboot,
        .mpo_check_system_settime = sebsd_check_system_settime,
	.mpo_check_system_swapon = sebsd_check_system_swapon,
	.mpo_check_system_swapoff = sebsd_check_system_swapoff,
	.mpo_check_system_sysctl = sebsd_check_system_sysctl,
	.mpo_check_vnode_access = sebsd_check_vnode_access,
	.mpo_check_vnode_chdir = sebsd_check_vnode_chdir,
	.mpo_check_vnode_chroot = sebsd_check_vnode_chroot,
	.mpo_check_vnode_create = sebsd_check_vnode_create,
	.mpo_check_vnode_delete = sebsd_check_vnode_delete,
	.mpo_check_vnode_deleteacl = sebsd_check_vnode_deleteacl,
	.mpo_check_vnode_exec = sebsd_check_vnode_exec,
	.mpo_check_vnode_getacl = sebsd_check_vnode_getacl,
	.mpo_check_vnode_getextattr = sebsd_check_vnode_getextattr,
	.mpo_check_vnode_link = sebsd_check_vnode_link,
	.mpo_check_vnode_lookup = sebsd_check_vnode_lookup,
	.mpo_check_vnode_mmap = sebsd_check_vnode_mmap,
#if 0
	/* XXXMAC: mprotect() is not checked by the MAC Framework. */
	.mpo_check_vnode_mprotect = sebsd_check_vnode_mmap,
#endif
	.mpo_check_vnode_open = sebsd_check_vnode_open,
	/* .mpo_check_vnode_poll = sebsd_check_vnode_poll, */
	.mpo_check_vnode_read = sebsd_check_vnode_read,
	.mpo_check_vnode_readdir = sebsd_check_vnode_readdir,
	.mpo_check_vnode_readlink = sebsd_check_vnode_readlink,
	.mpo_check_vnode_relabel = sebsd_check_vnode_relabel,
	.mpo_check_vnode_rename_from = sebsd_check_vnode_rename_from,
	.mpo_check_vnode_rename_to = sebsd_check_vnode_rename_to,
	.mpo_check_vnode_revoke = sebsd_check_vnode_revoke,
	.mpo_check_vnode_setacl = sebsd_check_vnode_setacl,
	.mpo_check_vnode_setextattr = sebsd_check_vnode_setextattr,
	.mpo_check_vnode_setflags = sebsd_check_vnode_setflags,
	.mpo_check_vnode_setmode = sebsd_check_vnode_setmode,
	.mpo_check_vnode_setowner = sebsd_check_vnode_setowner,
	.mpo_check_vnode_setutimes = sebsd_check_vnode_setutimes,
	.mpo_check_vnode_stat = sebsd_check_vnode_stat,
	.mpo_check_vnode_write = sebsd_check_vnode_write,

	/* Misc */
	.mpo_execve_transition = sebsd_execve_transition,
	.mpo_execve_will_transition = sebsd_execve_will_transition,
	.mpo_relabel_cred = sebsd_relabel_cred,
	.mpo_relabel_ifnet = sebsd_relabel_ifnet,
	.mpo_relabel_pipe = sebsd_relabel_pipe,
	.mpo_relabel_socket = sebsd_relabel_socket,
	.mpo_relabel_vnode = sebsd_relabel_vnode,
	.mpo_setlabel_vnode_extattr = sebsd_setlabel_vnode_extattr,
	//.mpo_set_socket_peer_from_mbuf = sebsd_set_socket_peer_from_mbuf,
	.mpo_set_socket_peer_from_socket = sebsd_set_socket_peer_from_socket,
	.mpo_cleanup_sysv_msgmsg = sebsd_cleanup_sysv_label,
	.mpo_cleanup_sysv_msgqueue = sebsd_cleanup_sysv_label,
	.mpo_cleanup_sysv_sem = sebsd_cleanup_sysv_label,
	.mpo_cleanup_sysv_shm = sebsd_cleanup_sysv_label,
	.mpo_syscall = sebsd_syscall,
};

MAC_POLICY_SET(&sebsd_ops, sebsd, "NSA/SPARTA Security Enhanced BSD",
    MPC_LOADTIME_FLAG_NOTLATE, &slot);
