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
 * $FreeBSD: src/sys/security/audit/audit_private.h,v 1.7 2006/03/19 17:34:00 rwatson Exp $
 */

/*
 * This include file contains function prototypes and type definitions used
 * within the audit implementation.
 */

#ifndef _SECURITY_AUDIT_PRIVATE_H_
#define	_SECURITY_AUDIT_PRIVATE_H_

#ifndef _KERNEL
#error "no user-serviceable parts inside"
#endif

#include <sys/ipc.h>
#include <sys/socket.h>
#include <sys/ucred.h>

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_AUDITBSM);
MALLOC_DECLARE(M_AUDITDATA);
MALLOC_DECLARE(M_AUDITPATH);
MALLOC_DECLARE(M_AUDITTEXT);
#endif

/*
 * The AUDIT_EXCESSIVELY_VERBOSE define enables a number of gratuitously
 * noisy printf's to the console.  Due to the volume, it should be left off
 * unless you want your system to churn a lot whenever the audit record flow
 * gets high.
 */
//#define	AUDIT_EXCESSIVELY_VERBOSE
#ifdef AUDIT_EXCESSIVELY_VERBOSE
#define	AUDIT_PRINTF(x)	printf x
#else
#define	AUDIT_PRINTF(x)
#endif

/*
 * Audit control variables that are usually set/read via system calls and
 * used to control various aspects of auditing.
 */
extern struct au_qctrl		audit_qctrl;
extern struct audit_fstat	audit_fstat;
extern struct au_mask		audit_nae_mask;
extern int			audit_panic_on_write_fail;
extern int			audit_fail_stop;

/*
 * Success/failure conditions for the conversion of a kernel audit record to
 * BSM format.
 */
#define	BSM_SUCCESS	0
#define	BSM_FAILURE	1
#define	BSM_NOAUDIT	2

/*
 * Defines for the kernel audit record k_ar_commit field.
 */
#define	AR_COMMIT_KERNEL	0x00000001U
#define	AR_COMMIT_USER		0x00000010U

/*
 * Audit data is generated as a stream of struct audit_record structures,
 * linked by struct kaudit_record, and contain storage for possible audit so
 * that it will not need to be allocated during the processing of a system
 * call, both improving efficiency and avoiding sleeping at untimely moments.
 * This structure is converted to BSM format before being written to disk.
 */
struct vnode_au_info {
	mode_t	vn_mode;
	uid_t	vn_uid;
	gid_t	vn_gid;
	dev_t	vn_dev;
	long	vn_fsid;
	long	vn_fileid;
	long	vn_gen;
};

struct groupset {
	gid_t	gidset[NGROUPS];
	u_int	gidset_size;
};

struct socket_au_info {
	int 		so_domain;
	int		so_type;
	int		so_protocol;
	in_addr_t	so_raddr;	/* Remote address if INET socket. */
	in_addr_t	so_laddr;	/* Local address if INET socket. */
	u_short		so_rport;	/* Remote port. */
	u_short		so_lport;	/* Local port. */
};

union auditon_udata {
	char			*au_path;
	long			au_cond;
	long			au_flags;
	long			au_policy;
	int			au_trigger;
	au_evclass_map_t	au_evclass;
	au_mask_t		au_mask;
	auditinfo_t		au_auinfo;
	auditpinfo_t		au_aupinfo;
	auditpinfo_addr_t	au_aupinfo_addr;
	au_qctrl_t		au_qctrl;
	au_stat_t		au_stat;
	au_fstat_t		au_fstat;
};

struct posix_ipc_perm {
	uid_t	pipc_uid;
	gid_t	pipc_gid;
	mode_t	pipc_mode;
};

struct audit_record {
	/* Audit record header. */
	u_int32_t		ar_magic;
	int			ar_event;
	int			ar_retval; /* value returned to the process */
	int			ar_errno;  /* return status of system call */
	struct timespec		ar_starttime;
	struct timespec		ar_endtime;
	u_int64_t		ar_valid_arg;  /* Bitmask of valid arguments */

	/* Audit subject information. */
	struct xucred		ar_subj_cred;
	uid_t			ar_subj_ruid;
	gid_t			ar_subj_rgid;
	gid_t			ar_subj_egid;
	uid_t			ar_subj_auid; /* Audit user ID */
	pid_t			ar_subj_asid; /* Audit session ID */
	pid_t			ar_subj_pid;
	struct au_tid		ar_subj_term;
	char			ar_subj_comm[MAXCOMLEN + 1];
	struct au_mask		ar_subj_amask;

	/* Operation arguments. */
	uid_t			ar_arg_euid;
	uid_t			ar_arg_ruid;
	uid_t			ar_arg_suid;
	gid_t			ar_arg_egid;
	gid_t			ar_arg_rgid;
	gid_t			ar_arg_sgid;
	pid_t			ar_arg_pid;
	pid_t			ar_arg_asid;
	struct au_tid		ar_arg_termid;
	uid_t			ar_arg_uid;
	uid_t			ar_arg_auid;
	gid_t			ar_arg_gid;
	struct groupset		ar_arg_groups;
	int			ar_arg_fd;
	int			ar_arg_fflags;
	mode_t			ar_arg_mode;
	int			ar_arg_dev;
	long			ar_arg_value;
	void *			ar_arg_addr;
	int			ar_arg_len;
	int			ar_arg_mask;
	u_int			ar_arg_signum;
	char			ar_arg_login[MAXLOGNAME];
	int			ar_arg_ctlname[CTL_MAXNAME];
	struct sockaddr		ar_arg_sockaddr;
	struct socket_au_info	ar_arg_sockinfo;
	char			*ar_arg_upath1;
	char			*ar_arg_upath2;
	char			*ar_arg_text;
	struct au_mask		ar_arg_amask;
	struct vnode_au_info	ar_arg_vnode1;
	struct vnode_au_info	ar_arg_vnode2;
	int			ar_arg_cmd;
	int			ar_arg_svipc_cmd;
	struct ipc_perm		ar_arg_svipc_perm;
	int			ar_arg_svipc_id;
	void *			ar_arg_svipc_addr;
	struct posix_ipc_perm	ar_arg_pipc_perm;
	union auditon_udata	ar_arg_auditon;
	int			ar_arg_exitstatus;
	int			ar_arg_exitretval;
};

/*
 * Arguments in the audit record are initially not defined; flags are set to
 * indicate if they are present so they can be included in the audit log
 * stream only if defined.
 */
#define	ARG_IS_VALID(kar, arg)	((kar)->k_ar.ar_valid_arg & (arg))
#define	ARG_SET_VALID(kar, arg) do {					\
	(kar)->k_ar.ar_valid_arg |= (arg);				\
} while (0)

/*
 * In-kernel version of audit record; the basic record plus queue meta-data.
 * This record can also have a pointer set to some opaque data that will be
 * passed through to the audit writing mechanism.
 */
struct kaudit_record {
	struct audit_record		 k_ar;
	u_int32_t			 k_ar_commit;
	void				*k_udata;	/* User data. */
	u_int				 k_ulen;	/* User data length. */
	struct uthread			*k_uthread;	/* Audited thread. */
	TAILQ_ENTRY(kaudit_record)	 k_q;
};
TAILQ_HEAD(kaudit_queue, kaudit_record);

/*
 * Functions to manage the allocation, release, and commit of kernel audit
 * records.
 */
void			 audit_abort(struct kaudit_record *ar);
void			 audit_commit(struct kaudit_record *ar, int error,
			    int retval);
struct kaudit_record	*audit_new(int event, struct thread *td);

/*
 * Functions relating to the conversion of internal kernel audit records to
 * the BSM file format.
 */
struct au_record;
int	 kaudit_to_bsm(struct kaudit_record *kar, struct au_record **pau);
int	 bsm_rec_verify(void *rec);

/*
 * Kernel versions of the libbsm audit record functions.
 */
void	 kau_free(struct au_record *rec);
void	 kau_init(void);

/*
 * Return values for pre-selection and post-selection decisions.
 */
#define	AU_PRS_SUCCESS	1
#define	AU_PRS_FAILURE	2
#define	AU_PRS_BOTH	(AU_PRS_SUCCESS|AU_PRS_FAILURE)

/*
 * Data structures relating to the kernel audit queue.  Ideally, these might
 * be abstracted so that only accessor methods are exposed.
 */
extern struct mtx		audit_mtx;
extern struct cv		audit_commit_cv;
extern struct cv		audit_cv;
extern struct kaudit_queue	audit_q;
extern int			audit_q_len;
extern int			audit_pre_q_len;
extern int			audit_in_failure;

/*
 * Flags to use on audit files when opening and closing.
 */
#define	AUDIT_OPEN_FLAGS	(FWRITE | O_APPEND)
#define	AUDIT_CLOSE_FLAGS	(FWRITE | O_APPEND)

#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

/*
 * Some of the BSM tokenizer functions take different parameters in the
 * kernel implementations in order to save the copying of large kernel data
 * structures. The prototypes of these functions are declared here.
 */
token_t		*kau_to_socket(struct socket_au_info *soi);

/*
 * audit_klib prototypes
 */
int		 au_preselect(au_event_t event, au_mask_t *mask_p, int sorf);
au_event_t	 flags_and_error_to_openevent(int oflags, int error);
void		 au_evclassmap_init(void);
void		 au_evclassmap_insert(au_event_t event, au_class_t class);
au_class_t	 au_event_class(au_event_t event);
au_event_t	 ctlname_to_sysctlevent(int name[], uint64_t valid_arg);
int		 auditon_command_event(int cmd);
int		 msgctl_to_event(int cmd);
int		 semctl_to_event(int cmr);
void		 canon_path(struct thread *td, char *path, char *cpath);

/*
 * Audit trigger events notify user space of kernel audit conditions
 * asynchronously.
 */
void		 audit_trigger_init(void);
int		 send_trigger(unsigned int trigger);

/*
 * General audit related functions.
 */
struct kaudit_record	*currecord(void);
void			 audit_free(struct kaudit_record *ar);
void			 audit_shutdown(void *arg, int howto);
void			 audit_rotate_vnode(struct ucred *cred,
			    struct vnode *vp);
void			 audit_worker_init(void);

/*
 * Audit pipe functions.
 */
void	 audit_pipe_submit(void *record, u_int record_len);

#endif /* ! _SECURITY_AUDIT_PRIVATE_H_ */
