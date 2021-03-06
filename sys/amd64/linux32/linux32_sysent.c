/*
 * System call switch table.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * $FreeBSD: src/sys/amd64/linux32/linux32_sysent.c,v 1.9 2006/03/19 11:12:41 ru Exp $
 * created from FreeBSD: src/sys/amd64/linux32/syscalls.master,v 1.7 2006/03/19 11:10:32 ru Exp 
 */

#include <bsm/audit_kevents.h>
#include "opt_compat.h"
#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <compat/linux/linux_sysproto.h>
#include <amd64/linux32/linux.h>
#include <amd64/linux32/linux32_proto.h>

#define AS(name) (sizeof(struct name) / sizeof(register_t))

/* The casts are bogus but will do for now. */
struct sysent linux_sysent[] = {
#define	nosys	linux_nosys
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 0 = setup */
	{ SYF_MPSAFE | AS(sys_exit_args), (sy_call_t *)sys_exit, AUE_NULL },	/* 1 = exit */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_fork, AUE_NULL },	/* 2 = linux_fork */
	{ SYF_MPSAFE | AS(read_args), (sy_call_t *)read, AUE_NULL },	/* 3 = read */
	{ SYF_MPSAFE | AS(write_args), (sy_call_t *)write, AUE_NULL },	/* 4 = write */
	{ SYF_MPSAFE | AS(linux_open_args), (sy_call_t *)linux_open, AUE_NULL },	/* 5 = linux_open */
	{ SYF_MPSAFE | AS(close_args), (sy_call_t *)close, AUE_NULL },	/* 6 = close */
	{ SYF_MPSAFE | AS(linux_waitpid_args), (sy_call_t *)linux_waitpid, AUE_NULL },	/* 7 = linux_waitpid */
	{ SYF_MPSAFE | AS(linux_creat_args), (sy_call_t *)linux_creat, AUE_NULL },	/* 8 = linux_creat */
	{ SYF_MPSAFE | AS(linux_link_args), (sy_call_t *)linux_link, AUE_NULL },	/* 9 = linux_link */
	{ SYF_MPSAFE | AS(linux_unlink_args), (sy_call_t *)linux_unlink, AUE_NULL },	/* 10 = linux_unlink */
	{ SYF_MPSAFE | AS(linux_execve_args), (sy_call_t *)linux_execve, AUE_NULL },	/* 11 = linux_execve */
	{ SYF_MPSAFE | AS(linux_chdir_args), (sy_call_t *)linux_chdir, AUE_NULL },	/* 12 = linux_chdir */
	{ SYF_MPSAFE | AS(linux_time_args), (sy_call_t *)linux_time, AUE_NULL },	/* 13 = linux_time */
	{ SYF_MPSAFE | AS(linux_mknod_args), (sy_call_t *)linux_mknod, AUE_NULL },	/* 14 = linux_mknod */
	{ SYF_MPSAFE | AS(linux_chmod_args), (sy_call_t *)linux_chmod, AUE_NULL },	/* 15 = linux_chmod */
	{ SYF_MPSAFE | AS(linux_lchown16_args), (sy_call_t *)linux_lchown16, AUE_NULL },	/* 16 = linux_lchown16 */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 17 = break */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 18 = stat */
	{ SYF_MPSAFE | AS(linux_lseek_args), (sy_call_t *)linux_lseek, AUE_NULL },	/* 19 = linux_lseek */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getpid, AUE_NULL },	/* 20 = linux_getpid */
	{ AS(linux_mount_args), (sy_call_t *)linux_mount, AUE_NULL },	/* 21 = linux_mount */
	{ AS(linux_oldumount_args), (sy_call_t *)linux_oldumount, AUE_NULL },	/* 22 = linux_oldumount */
	{ SYF_MPSAFE | AS(linux_setuid16_args), (sy_call_t *)linux_setuid16, AUE_NULL },	/* 23 = linux_setuid16 */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getuid16, AUE_NULL },	/* 24 = linux_getuid16 */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_stime, AUE_NULL },	/* 25 = linux_stime */
	{ SYF_MPSAFE | AS(linux_ptrace_args), (sy_call_t *)linux_ptrace, AUE_NULL },	/* 26 = linux_ptrace */
	{ SYF_MPSAFE | AS(linux_alarm_args), (sy_call_t *)linux_alarm, AUE_NULL },	/* 27 = linux_alarm */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 28 = fstat */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_pause, AUE_NULL },	/* 29 = linux_pause */
	{ SYF_MPSAFE | AS(linux_utime_args), (sy_call_t *)linux_utime, AUE_NULL },	/* 30 = linux_utime */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 31 = stty */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 32 = gtty */
	{ SYF_MPSAFE | AS(linux_access_args), (sy_call_t *)linux_access, AUE_NULL },	/* 33 = linux_access */
	{ SYF_MPSAFE | AS(linux_nice_args), (sy_call_t *)linux_nice, AUE_NULL },	/* 34 = linux_nice */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 35 = ftime */
	{ SYF_MPSAFE | 0, (sy_call_t *)sync, AUE_NULL },	/* 36 = sync */
	{ SYF_MPSAFE | AS(linux_kill_args), (sy_call_t *)linux_kill, AUE_NULL },	/* 37 = linux_kill */
	{ SYF_MPSAFE | AS(linux_rename_args), (sy_call_t *)linux_rename, AUE_NULL },	/* 38 = linux_rename */
	{ SYF_MPSAFE | AS(linux_mkdir_args), (sy_call_t *)linux_mkdir, AUE_NULL },	/* 39 = linux_mkdir */
	{ SYF_MPSAFE | AS(linux_rmdir_args), (sy_call_t *)linux_rmdir, AUE_NULL },	/* 40 = linux_rmdir */
	{ SYF_MPSAFE | AS(dup_args), (sy_call_t *)dup, AUE_NULL },	/* 41 = dup */
	{ SYF_MPSAFE | AS(linux_pipe_args), (sy_call_t *)linux_pipe, AUE_NULL },	/* 42 = linux_pipe */
	{ SYF_MPSAFE | AS(linux_times_args), (sy_call_t *)linux_times, AUE_NULL },	/* 43 = linux_times */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 44 = prof */
	{ AS(linux_brk_args), (sy_call_t *)linux_brk, AUE_NULL },	/* 45 = linux_brk */
	{ SYF_MPSAFE | AS(linux_setgid16_args), (sy_call_t *)linux_setgid16, AUE_NULL },	/* 46 = linux_setgid16 */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getgid16, AUE_NULL },	/* 47 = linux_getgid16 */
	{ SYF_MPSAFE | AS(linux_signal_args), (sy_call_t *)linux_signal, AUE_NULL },	/* 48 = linux_signal */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_geteuid16, AUE_NULL },	/* 49 = linux_geteuid16 */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getegid16, AUE_NULL },	/* 50 = linux_getegid16 */
	{ SYF_MPSAFE | AS(acct_args), (sy_call_t *)acct, AUE_NULL },	/* 51 = acct */
	{ AS(linux_umount_args), (sy_call_t *)linux_umount, AUE_NULL },	/* 52 = linux_umount */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 53 = lock */
	{ AS(linux_ioctl_args), (sy_call_t *)linux_ioctl, AUE_NULL },	/* 54 = linux_ioctl */
	{ SYF_MPSAFE | AS(linux_fcntl_args), (sy_call_t *)linux_fcntl, AUE_NULL },	/* 55 = linux_fcntl */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 56 = mpx */
	{ SYF_MPSAFE | AS(setpgid_args), (sy_call_t *)setpgid, AUE_NULL },	/* 57 = setpgid */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 58 = ulimit */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_olduname, AUE_NULL },	/* 59 = linux_olduname */
	{ SYF_MPSAFE | AS(umask_args), (sy_call_t *)umask, AUE_NULL },	/* 60 = umask */
	{ SYF_MPSAFE | AS(chroot_args), (sy_call_t *)chroot, AUE_NULL },	/* 61 = chroot */
	{ SYF_MPSAFE | AS(linux_ustat_args), (sy_call_t *)linux_ustat, AUE_NULL },	/* 62 = linux_ustat */
	{ SYF_MPSAFE | AS(dup2_args), (sy_call_t *)dup2, AUE_NULL },	/* 63 = dup2 */
	{ SYF_MPSAFE | 0, (sy_call_t *)getppid, AUE_NULL },	/* 64 = getppid */
	{ SYF_MPSAFE | 0, (sy_call_t *)getpgrp, AUE_NULL },	/* 65 = getpgrp */
	{ SYF_MPSAFE | 0, (sy_call_t *)setsid, AUE_NULL },	/* 66 = setsid */
	{ SYF_MPSAFE | AS(linux_sigaction_args), (sy_call_t *)linux_sigaction, AUE_NULL },	/* 67 = linux_sigaction */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_sgetmask, AUE_NULL },	/* 68 = linux_sgetmask */
	{ SYF_MPSAFE | AS(linux_ssetmask_args), (sy_call_t *)linux_ssetmask, AUE_NULL },	/* 69 = linux_ssetmask */
	{ SYF_MPSAFE | AS(linux_setreuid16_args), (sy_call_t *)linux_setreuid16, AUE_NULL },	/* 70 = linux_setreuid16 */
	{ SYF_MPSAFE | AS(linux_setregid16_args), (sy_call_t *)linux_setregid16, AUE_NULL },	/* 71 = linux_setregid16 */
	{ SYF_MPSAFE | AS(linux_sigsuspend_args), (sy_call_t *)linux_sigsuspend, AUE_NULL },	/* 72 = linux_sigsuspend */
	{ SYF_MPSAFE | AS(linux_sigpending_args), (sy_call_t *)linux_sigpending, AUE_NULL },	/* 73 = linux_sigpending */
	{ SYF_MPSAFE | AS(linux_sethostname_args), (sy_call_t *)linux_sethostname, AUE_NULL },	/* 74 = linux_sethostname */
	{ SYF_MPSAFE | AS(linux_setrlimit_args), (sy_call_t *)linux_setrlimit, AUE_NULL },	/* 75 = linux_setrlimit */
	{ SYF_MPSAFE | AS(linux_old_getrlimit_args), (sy_call_t *)linux_old_getrlimit, AUE_NULL },	/* 76 = linux_old_getrlimit */
	{ SYF_MPSAFE | AS(linux_getrusage_args), (sy_call_t *)linux_getrusage, AUE_NULL },	/* 77 = linux_getrusage */
	{ SYF_MPSAFE | AS(linux_gettimeofday_args), (sy_call_t *)linux_gettimeofday, AUE_NULL },	/* 78 = linux_gettimeofday */
	{ SYF_MPSAFE | AS(linux_settimeofday_args), (sy_call_t *)linux_settimeofday, AUE_NULL },	/* 79 = linux_settimeofday */
	{ SYF_MPSAFE | AS(linux_getgroups16_args), (sy_call_t *)linux_getgroups16, AUE_NULL },	/* 80 = linux_getgroups16 */
	{ SYF_MPSAFE | AS(linux_setgroups16_args), (sy_call_t *)linux_setgroups16, AUE_NULL },	/* 81 = linux_setgroups16 */
	{ SYF_MPSAFE | AS(linux_old_select_args), (sy_call_t *)linux_old_select, AUE_NULL },	/* 82 = linux_old_select */
	{ SYF_MPSAFE | AS(linux_symlink_args), (sy_call_t *)linux_symlink, AUE_NULL },	/* 83 = linux_symlink */
	{ SYF_MPSAFE | AS(linux_stat_args), (sy_call_t *)linux_stat, AUE_NULL },	/* 84 = linux_stat */
	{ SYF_MPSAFE | AS(linux_readlink_args), (sy_call_t *)linux_readlink, AUE_NULL },	/* 85 = linux_readlink */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 86 = linux_uselib */
	{ SYF_MPSAFE | AS(swapon_args), (sy_call_t *)swapon, AUE_NULL },	/* 87 = swapon */
	{ SYF_MPSAFE | AS(linux_reboot_args), (sy_call_t *)linux_reboot, AUE_NULL },	/* 88 = linux_reboot */
	{ AS(linux_readdir_args), (sy_call_t *)linux_readdir, AUE_NULL },	/* 89 = linux_readdir */
	{ SYF_MPSAFE | AS(linux_mmap_args), (sy_call_t *)linux_mmap, AUE_NULL },	/* 90 = linux_mmap */
	{ SYF_MPSAFE | AS(munmap_args), (sy_call_t *)munmap, AUE_NULL },	/* 91 = munmap */
	{ SYF_MPSAFE | AS(linux_truncate_args), (sy_call_t *)linux_truncate, AUE_NULL },	/* 92 = linux_truncate */
	{ SYF_MPSAFE | AS(linux_ftruncate_args), (sy_call_t *)linux_ftruncate, AUE_NULL },	/* 93 = linux_ftruncate */
	{ SYF_MPSAFE | AS(fchmod_args), (sy_call_t *)fchmod, AUE_NULL },	/* 94 = fchmod */
	{ SYF_MPSAFE | AS(fchown_args), (sy_call_t *)fchown, AUE_NULL },	/* 95 = fchown */
	{ SYF_MPSAFE | AS(linux_getpriority_args), (sy_call_t *)linux_getpriority, AUE_NULL },	/* 96 = linux_getpriority */
	{ SYF_MPSAFE | AS(setpriority_args), (sy_call_t *)setpriority, AUE_NULL },	/* 97 = setpriority */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 98 = profil */
	{ SYF_MPSAFE | AS(linux_statfs_args), (sy_call_t *)linux_statfs, AUE_NULL },	/* 99 = linux_statfs */
	{ SYF_MPSAFE | AS(linux_fstatfs_args), (sy_call_t *)linux_fstatfs, AUE_NULL },	/* 100 = linux_fstatfs */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 101 = ioperm */
	{ SYF_MPSAFE | AS(linux_socketcall_args), (sy_call_t *)linux_socketcall, AUE_NULL },	/* 102 = linux_socketcall */
	{ SYF_MPSAFE | AS(linux_syslog_args), (sy_call_t *)linux_syslog, AUE_NULL },	/* 103 = linux_syslog */
	{ SYF_MPSAFE | AS(linux_setitimer_args), (sy_call_t *)linux_setitimer, AUE_NULL },	/* 104 = linux_setitimer */
	{ SYF_MPSAFE | AS(linux_getitimer_args), (sy_call_t *)linux_getitimer, AUE_NULL },	/* 105 = linux_getitimer */
	{ SYF_MPSAFE | AS(linux_newstat_args), (sy_call_t *)linux_newstat, AUE_NULL },	/* 106 = linux_newstat */
	{ SYF_MPSAFE | AS(linux_newlstat_args), (sy_call_t *)linux_newlstat, AUE_NULL },	/* 107 = linux_newlstat */
	{ SYF_MPSAFE | AS(linux_newfstat_args), (sy_call_t *)linux_newfstat, AUE_NULL },	/* 108 = linux_newfstat */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_uname, AUE_NULL },	/* 109 = linux_uname */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 110 = iopl */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_vhangup, AUE_NULL },	/* 111 = linux_vhangup */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 112 = idle */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 113 = vm86old */
	{ SYF_MPSAFE | AS(linux_wait4_args), (sy_call_t *)linux_wait4, AUE_NULL },	/* 114 = linux_wait4 */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_swapoff, AUE_NULL },	/* 115 = linux_swapoff */
	{ SYF_MPSAFE | AS(linux_sysinfo_args), (sy_call_t *)linux_sysinfo, AUE_NULL },	/* 116 = linux_sysinfo */
	{ AS(linux_ipc_args), (sy_call_t *)linux_ipc, AUE_NULL },	/* 117 = linux_ipc */
	{ SYF_MPSAFE | AS(fsync_args), (sy_call_t *)fsync, AUE_NULL },	/* 118 = fsync */
	{ SYF_MPSAFE | AS(linux_sigreturn_args), (sy_call_t *)linux_sigreturn, AUE_NULL },	/* 119 = linux_sigreturn */
	{ SYF_MPSAFE | AS(linux_clone_args), (sy_call_t *)linux_clone, AUE_NULL },	/* 120 = linux_clone */
	{ SYF_MPSAFE | AS(setdomainname_args), (sy_call_t *)setdomainname, AUE_NULL },	/* 121 = setdomainname */
	{ SYF_MPSAFE | AS(linux_newuname_args), (sy_call_t *)linux_newuname, AUE_NULL },	/* 122 = linux_newuname */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 123 = modify_ldt */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_adjtimex, AUE_NULL },	/* 124 = linux_adjtimex */
	{ SYF_MPSAFE | AS(linux_mprotect_args), (sy_call_t *)linux_mprotect, AUE_NULL },	/* 125 = linux_mprotect */
	{ SYF_MPSAFE | AS(linux_sigprocmask_args), (sy_call_t *)linux_sigprocmask, AUE_NULL },	/* 126 = linux_sigprocmask */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_create_module, AUE_NULL },	/* 127 = linux_create_module */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_init_module, AUE_NULL },	/* 128 = linux_init_module */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_delete_module, AUE_NULL },	/* 129 = linux_delete_module */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_get_kernel_syms, AUE_NULL },	/* 130 = linux_get_kernel_syms */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_quotactl, AUE_NULL },	/* 131 = linux_quotactl */
	{ SYF_MPSAFE | AS(getpgid_args), (sy_call_t *)getpgid, AUE_NULL },	/* 132 = getpgid */
	{ SYF_MPSAFE | AS(fchdir_args), (sy_call_t *)fchdir, AUE_NULL },	/* 133 = fchdir */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_bdflush, AUE_NULL },	/* 134 = linux_bdflush */
	{ SYF_MPSAFE | AS(linux_sysfs_args), (sy_call_t *)linux_sysfs, AUE_NULL },	/* 135 = linux_sysfs */
	{ SYF_MPSAFE | AS(linux_personality_args), (sy_call_t *)linux_personality, AUE_NULL },	/* 136 = linux_personality */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 137 = afs_syscall */
	{ SYF_MPSAFE | AS(linux_setfsuid16_args), (sy_call_t *)linux_setfsuid16, AUE_NULL },	/* 138 = linux_setfsuid16 */
	{ SYF_MPSAFE | AS(linux_setfsgid16_args), (sy_call_t *)linux_setfsgid16, AUE_NULL },	/* 139 = linux_setfsgid16 */
	{ SYF_MPSAFE | AS(linux_llseek_args), (sy_call_t *)linux_llseek, AUE_NULL },	/* 140 = linux_llseek */
	{ AS(linux_getdents_args), (sy_call_t *)linux_getdents, AUE_NULL },	/* 141 = linux_getdents */
	{ SYF_MPSAFE | AS(linux_select_args), (sy_call_t *)linux_select, AUE_NULL },	/* 142 = linux_select */
	{ SYF_MPSAFE | AS(flock_args), (sy_call_t *)flock, AUE_NULL },	/* 143 = flock */
	{ SYF_MPSAFE | AS(linux_msync_args), (sy_call_t *)linux_msync, AUE_NULL },	/* 144 = linux_msync */
	{ SYF_MPSAFE | AS(linux_readv_args), (sy_call_t *)linux_readv, AUE_NULL },	/* 145 = linux_readv */
	{ SYF_MPSAFE | AS(linux_writev_args), (sy_call_t *)linux_writev, AUE_NULL },	/* 146 = linux_writev */
	{ SYF_MPSAFE | AS(linux_getsid_args), (sy_call_t *)linux_getsid, AUE_NULL },	/* 147 = linux_getsid */
	{ SYF_MPSAFE | AS(linux_fdatasync_args), (sy_call_t *)linux_fdatasync, AUE_NULL },	/* 148 = linux_fdatasync */
	{ SYF_MPSAFE | AS(linux_sysctl_args), (sy_call_t *)linux_sysctl, AUE_NULL },	/* 149 = linux_sysctl */
	{ SYF_MPSAFE | AS(mlock_args), (sy_call_t *)mlock, AUE_NULL },	/* 150 = mlock */
	{ SYF_MPSAFE | AS(munlock_args), (sy_call_t *)munlock, AUE_NULL },	/* 151 = munlock */
	{ SYF_MPSAFE | AS(mlockall_args), (sy_call_t *)mlockall, AUE_NULL },	/* 152 = mlockall */
	{ SYF_MPSAFE | 0, (sy_call_t *)munlockall, AUE_NULL },	/* 153 = munlockall */
	{ SYF_MPSAFE | AS(sched_setparam_args), (sy_call_t *)sched_setparam, AUE_NULL },	/* 154 = sched_setparam */
	{ SYF_MPSAFE | AS(sched_getparam_args), (sy_call_t *)sched_getparam, AUE_NULL },	/* 155 = sched_getparam */
	{ SYF_MPSAFE | AS(linux_sched_setscheduler_args), (sy_call_t *)linux_sched_setscheduler, AUE_NULL },	/* 156 = linux_sched_setscheduler */
	{ SYF_MPSAFE | AS(linux_sched_getscheduler_args), (sy_call_t *)linux_sched_getscheduler, AUE_NULL },	/* 157 = linux_sched_getscheduler */
	{ SYF_MPSAFE | 0, (sy_call_t *)sched_yield, AUE_NULL },	/* 158 = sched_yield */
	{ SYF_MPSAFE | AS(linux_sched_get_priority_max_args), (sy_call_t *)linux_sched_get_priority_max, AUE_NULL },	/* 159 = linux_sched_get_priority_max */
	{ SYF_MPSAFE | AS(linux_sched_get_priority_min_args), (sy_call_t *)linux_sched_get_priority_min, AUE_NULL },	/* 160 = linux_sched_get_priority_min */
	{ SYF_MPSAFE | AS(linux_sched_rr_get_interval_args), (sy_call_t *)linux_sched_rr_get_interval, AUE_NULL },	/* 161 = linux_sched_rr_get_interval */
	{ SYF_MPSAFE | AS(linux_nanosleep_args), (sy_call_t *)linux_nanosleep, AUE_NULL },	/* 162 = linux_nanosleep */
	{ SYF_MPSAFE | AS(linux_mremap_args), (sy_call_t *)linux_mremap, AUE_NULL },	/* 163 = linux_mremap */
	{ SYF_MPSAFE | AS(linux_setresuid16_args), (sy_call_t *)linux_setresuid16, AUE_NULL },	/* 164 = linux_setresuid16 */
	{ SYF_MPSAFE | AS(linux_getresuid16_args), (sy_call_t *)linux_getresuid16, AUE_NULL },	/* 165 = linux_getresuid16 */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 166 = vm86 */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_query_module, AUE_NULL },	/* 167 = linux_query_module */
	{ SYF_MPSAFE | AS(poll_args), (sy_call_t *)poll, AUE_NULL },	/* 168 = poll */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_nfsservctl, AUE_NULL },	/* 169 = linux_nfsservctl */
	{ SYF_MPSAFE | AS(linux_setresgid16_args), (sy_call_t *)linux_setresgid16, AUE_NULL },	/* 170 = linux_setresgid16 */
	{ SYF_MPSAFE | AS(linux_getresgid16_args), (sy_call_t *)linux_getresgid16, AUE_NULL },	/* 171 = linux_getresgid16 */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_prctl, AUE_NULL },	/* 172 = linux_prctl */
	{ SYF_MPSAFE | AS(linux_rt_sigreturn_args), (sy_call_t *)linux_rt_sigreturn, AUE_NULL },	/* 173 = linux_rt_sigreturn */
	{ SYF_MPSAFE | AS(linux_rt_sigaction_args), (sy_call_t *)linux_rt_sigaction, AUE_NULL },	/* 174 = linux_rt_sigaction */
	{ SYF_MPSAFE | AS(linux_rt_sigprocmask_args), (sy_call_t *)linux_rt_sigprocmask, AUE_NULL },	/* 175 = linux_rt_sigprocmask */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_rt_sigpending, AUE_NULL },	/* 176 = linux_rt_sigpending */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_rt_sigtimedwait, AUE_NULL },	/* 177 = linux_rt_sigtimedwait */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_rt_sigqueueinfo, AUE_NULL },	/* 178 = linux_rt_sigqueueinfo */
	{ SYF_MPSAFE | AS(linux_rt_sigsuspend_args), (sy_call_t *)linux_rt_sigsuspend, AUE_NULL },	/* 179 = linux_rt_sigsuspend */
	{ SYF_MPSAFE | AS(linux_pread_args), (sy_call_t *)linux_pread, AUE_NULL },	/* 180 = linux_pread */
	{ SYF_MPSAFE | AS(linux_pwrite_args), (sy_call_t *)linux_pwrite, AUE_NULL },	/* 181 = linux_pwrite */
	{ SYF_MPSAFE | AS(linux_chown16_args), (sy_call_t *)linux_chown16, AUE_NULL },	/* 182 = linux_chown16 */
	{ SYF_MPSAFE | AS(linux_getcwd_args), (sy_call_t *)linux_getcwd, AUE_NULL },	/* 183 = linux_getcwd */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_capget, AUE_NULL },	/* 184 = linux_capget */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_capset, AUE_NULL },	/* 185 = linux_capset */
	{ SYF_MPSAFE | AS(linux_sigaltstack_args), (sy_call_t *)linux_sigaltstack, AUE_NULL },	/* 186 = linux_sigaltstack */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_sendfile, AUE_NULL },	/* 187 = linux_sendfile */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 188 = getpmsg */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 189 = putpmsg */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_vfork, AUE_NULL },	/* 190 = linux_vfork */
	{ SYF_MPSAFE | AS(linux_getrlimit_args), (sy_call_t *)linux_getrlimit, AUE_NULL },	/* 191 = linux_getrlimit */
	{ SYF_MPSAFE | AS(linux_mmap2_args), (sy_call_t *)linux_mmap2, AUE_NULL },	/* 192 = linux_mmap2 */
	{ SYF_MPSAFE | AS(linux_truncate64_args), (sy_call_t *)linux_truncate64, AUE_NULL },	/* 193 = linux_truncate64 */
	{ SYF_MPSAFE | AS(linux_ftruncate64_args), (sy_call_t *)linux_ftruncate64, AUE_NULL },	/* 194 = linux_ftruncate64 */
	{ SYF_MPSAFE | AS(linux_stat64_args), (sy_call_t *)linux_stat64, AUE_NULL },	/* 195 = linux_stat64 */
	{ SYF_MPSAFE | AS(linux_lstat64_args), (sy_call_t *)linux_lstat64, AUE_NULL },	/* 196 = linux_lstat64 */
	{ SYF_MPSAFE | AS(linux_fstat64_args), (sy_call_t *)linux_fstat64, AUE_NULL },	/* 197 = linux_fstat64 */
	{ SYF_MPSAFE | AS(linux_lchown_args), (sy_call_t *)linux_lchown, AUE_NULL },	/* 198 = linux_lchown */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getuid, AUE_NULL },	/* 199 = linux_getuid */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getgid, AUE_NULL },	/* 200 = linux_getgid */
	{ SYF_MPSAFE | 0, (sy_call_t *)geteuid, AUE_NULL },	/* 201 = geteuid */
	{ SYF_MPSAFE | 0, (sy_call_t *)getegid, AUE_NULL },	/* 202 = getegid */
	{ SYF_MPSAFE | AS(setreuid_args), (sy_call_t *)setreuid, AUE_NULL },	/* 203 = setreuid */
	{ SYF_MPSAFE | AS(setregid_args), (sy_call_t *)setregid, AUE_NULL },	/* 204 = setregid */
	{ SYF_MPSAFE | AS(linux_getgroups_args), (sy_call_t *)linux_getgroups, AUE_NULL },	/* 205 = linux_getgroups */
	{ SYF_MPSAFE | AS(linux_setgroups_args), (sy_call_t *)linux_setgroups, AUE_NULL },	/* 206 = linux_setgroups */
	{ AS(fchown_args), (sy_call_t *)fchown, AUE_NULL },	/* 207 = fchown */
	{ SYF_MPSAFE | AS(setresuid_args), (sy_call_t *)setresuid, AUE_NULL },	/* 208 = setresuid */
	{ SYF_MPSAFE | AS(getresuid_args), (sy_call_t *)getresuid, AUE_NULL },	/* 209 = getresuid */
	{ SYF_MPSAFE | AS(setresgid_args), (sy_call_t *)setresgid, AUE_NULL },	/* 210 = setresgid */
	{ SYF_MPSAFE | AS(getresgid_args), (sy_call_t *)getresgid, AUE_NULL },	/* 211 = getresgid */
	{ SYF_MPSAFE | AS(linux_chown_args), (sy_call_t *)linux_chown, AUE_NULL },	/* 212 = linux_chown */
	{ SYF_MPSAFE | AS(setuid_args), (sy_call_t *)setuid, AUE_NULL },	/* 213 = setuid */
	{ SYF_MPSAFE | AS(setgid_args), (sy_call_t *)setgid, AUE_NULL },	/* 214 = setgid */
	{ SYF_MPSAFE | AS(linux_setfsuid_args), (sy_call_t *)linux_setfsuid, AUE_NULL },	/* 215 = linux_setfsuid */
	{ SYF_MPSAFE | AS(linux_setfsgid_args), (sy_call_t *)linux_setfsgid, AUE_NULL },	/* 216 = linux_setfsgid */
	{ SYF_MPSAFE | AS(linux_pivot_root_args), (sy_call_t *)linux_pivot_root, AUE_NULL },	/* 217 = linux_pivot_root */
	{ SYF_MPSAFE | AS(linux_mincore_args), (sy_call_t *)linux_mincore, AUE_NULL },	/* 218 = linux_mincore */
	{ SYF_MPSAFE | AS(madvise_args), (sy_call_t *)madvise, AUE_NULL },	/* 219 = madvise */
	{ AS(linux_getdents64_args), (sy_call_t *)linux_getdents64, AUE_NULL },	/* 220 = linux_getdents64 */
	{ SYF_MPSAFE | AS(linux_fcntl64_args), (sy_call_t *)linux_fcntl64, AUE_NULL },	/* 221 = linux_fcntl64 */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 222 =  */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 223 =  */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getpid, AUE_NULL },	/* 224 = gettid */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 225 = linux_readahead */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_setxattr, AUE_NULL },	/* 226 = linux_setxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_lsetxattr, AUE_NULL },	/* 227 = linux_lsetxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_fsetxattr, AUE_NULL },	/* 228 = linux_fsetxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_getxattr, AUE_NULL },	/* 229 = linux_getxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_lgetxattr, AUE_NULL },	/* 230 = linux_lgetxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_fgetxattr, AUE_NULL },	/* 231 = linux_fgetxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_listxattr, AUE_NULL },	/* 232 = linux_listxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_llistxattr, AUE_NULL },	/* 233 = linux_llistxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_flistxattr, AUE_NULL },	/* 234 = linux_flistxattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_removexattr, AUE_NULL },	/* 235 = linux_removexattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_lremovexattr, AUE_NULL },	/* 236 = linux_lremovexattr */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_fremovexattr, AUE_NULL },	/* 237 = linux_fremovexattr */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 238 = linux_tkill */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 239 = linux_sendfile64 */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 240 = linux_futex */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 241 = linux_sched_setaffinity */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 242 = linux_sched_getaffinity */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 243 = linux_set_thread_area */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 244 = linux_get_thread_area */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 245 = linux_io_setup */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 246 = linux_io_destroy */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 247 = linux_io_getevents */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 248 = linux_io_submit */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 249 = linux_io_cancel */
	{ SYF_MPSAFE | 0, (sy_call_t *)linux_fadvise64, AUE_NULL },	/* 250 = linux_fadvise64 */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 251 =  */
	{ SYF_MPSAFE | AS(sys_exit_args), (sy_call_t *)sys_exit, AUE_NULL },	/* 252 = exit_group */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 253 = linux_lookup_dcookie */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 254 = linux_epoll_create */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 255 = linux_epoll_ctl */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 256 = linux_epoll_wait */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 257 = linux_remap_file_pages */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 258 = linux_set_tid_address */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 259 = linux_timer_create */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 260 = linux_timer_settime */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 261 = linux_timer_gettime */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 262 = linux_timer_getoverrun */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 263 = linux_timer_delete */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 264 = linux_clock_settime */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 265 = linux_clock_gettime */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 266 = linux_clock_getres */
	{ 0, (sy_call_t *)nosys, AUE_NULL },			/* 267 = linux_clock_nanosleep */
};
