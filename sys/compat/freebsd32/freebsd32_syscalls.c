/*
 * System call names.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * $FreeBSD: src/sys/compat/freebsd32/freebsd32_syscalls.c,v 1.42 2006/02/28 19:39:52 ps Exp $
 * created from FreeBSD
 */

const char *freebsd32_syscallnames[] = {
	"syscall",			/* 0 = syscall */
	"exit",			/* 1 = exit */
	"fork",			/* 2 = fork */
	"read",			/* 3 = read */
	"write",			/* 4 = write */
	"open",			/* 5 = open */
	"close",			/* 6 = close */
	"freebsd32_wait4",			/* 7 = freebsd32_wait4 */
	"obs_old",			/* 8 = obsolete old creat */
	"link",			/* 9 = link */
	"unlink",			/* 10 = unlink */
	"obs_execv",			/* 11 = obsolete execv */
	"chdir",			/* 12 = chdir */
	"fchdir",			/* 13 = fchdir */
	"mknod",			/* 14 = mknod */
	"chmod",			/* 15 = chmod */
	"chown",			/* 16 = chown */
	"break",			/* 17 = break */
	"old.freebsd32_getfsstat",		/* 18 = old freebsd32_getfsstat */
	"obs_olseek",			/* 19 = obsolete olseek */
	"getpid",			/* 20 = getpid */
	"mount",			/* 21 = mount */
	"unmount",			/* 22 = unmount */
	"setuid",			/* 23 = setuid */
	"getuid",			/* 24 = getuid */
	"geteuid",			/* 25 = geteuid */
	"ptrace",			/* 26 = ptrace */
	"freebsd32_recvmsg",			/* 27 = freebsd32_recvmsg */
	"freebsd32_sendmsg",			/* 28 = freebsd32_sendmsg */
	"freebsd32_recvfrom",			/* 29 = freebsd32_recvfrom */
	"accept",			/* 30 = accept */
	"getpeername",			/* 31 = getpeername */
	"getsockname",			/* 32 = getsockname */
	"access",			/* 33 = access */
	"chflags",			/* 34 = chflags */
	"fchflags",			/* 35 = fchflags */
	"sync",			/* 36 = sync */
	"kill",			/* 37 = kill */
	"#38",			/* 38 = ostat */
	"getppid",			/* 39 = getppid */
	"#40",			/* 40 = olstat */
	"dup",			/* 41 = dup */
	"pipe",			/* 42 = pipe */
	"getegid",			/* 43 = getegid */
	"profil",			/* 44 = profil */
	"ktrace",			/* 45 = ktrace */
	"old.freebsd32_sigaction",		/* 46 = old freebsd32_sigaction */
	"getgid",			/* 47 = getgid */
	"old.freebsd32_sigprocmask",		/* 48 = old freebsd32_sigprocmask */
	"getlogin",			/* 49 = getlogin */
	"setlogin",			/* 50 = setlogin */
	"acct",			/* 51 = acct */
	"old.freebsd32_sigpending",		/* 52 = old freebsd32_sigpending */
	"freebsd32_sigaltstack",			/* 53 = freebsd32_sigaltstack */
	"ioctl",			/* 54 = ioctl */
	"reboot",			/* 55 = reboot */
	"revoke",			/* 56 = revoke */
	"symlink",			/* 57 = symlink */
	"readlink",			/* 58 = readlink */
	"freebsd32_execve",			/* 59 = freebsd32_execve */
	"umask",			/* 60 = umask */
	"chroot",			/* 61 = chroot */
	"obs_ofstat",			/* 62 = obsolete ofstat */
	"obs_ogetkerninfo",			/* 63 = obsolete ogetkerninfo */
	"obs_ogetpagesize",			/* 64 = obsolete ogetpagesize */
	"msync",			/* 65 = msync */
	"vfork",			/* 66 = vfork */
	"obs_vread",			/* 67 = obsolete vread */
	"obs_vwrite",			/* 68 = obsolete vwrite */
	"sbrk",			/* 69 = sbrk */
	"sstk",			/* 70 = sstk */
	"obs_ommap",			/* 71 = obsolete ommap */
	"vadvise",			/* 72 = vadvise */
	"munmap",			/* 73 = munmap */
	"mprotect",			/* 74 = mprotect */
	"madvise",			/* 75 = madvise */
	"obs_vhangup",			/* 76 = obsolete vhangup */
	"obs_vlimit",			/* 77 = obsolete vlimit */
	"mincore",			/* 78 = mincore */
	"getgroups",			/* 79 = getgroups */
	"setgroups",			/* 80 = setgroups */
	"getpgrp",			/* 81 = getpgrp */
	"setpgid",			/* 82 = setpgid */
	"freebsd32_setitimer",			/* 83 = freebsd32_setitimer */
	"obs_owait",			/* 84 = obsolete owait */
	"obs_oswapon",			/* 85 = obsolete oswapon */
	"freebsd32_getitimer",			/* 86 = freebsd32_getitimer */
	"obs_ogethostname",			/* 87 = obsolete ogethostname */
	"obs_osethostname",			/* 88 = obsolete osethostname */
	"getdtablesize",			/* 89 = getdtablesize */
	"dup2",			/* 90 = dup2 */
	"#91",			/* 91 = getdopt */
	"fcntl",			/* 92 = fcntl */
	"freebsd32_select",			/* 93 = freebsd32_select */
	"#94",			/* 94 = setdopt */
	"fsync",			/* 95 = fsync */
	"setpriority",			/* 96 = setpriority */
	"socket",			/* 97 = socket */
	"connect",			/* 98 = connect */
	"obs_oaccept",			/* 99 = obsolete oaccept */
	"getpriority",			/* 100 = getpriority */
	"obs_osend",			/* 101 = obsolete osend */
	"obs_orecv",			/* 102 = obsolete orecv */
	"obs_osigreturn",			/* 103 = obsolete osigreturn */
	"bind",			/* 104 = bind */
	"setsockopt",			/* 105 = setsockopt */
	"listen",			/* 106 = listen */
	"obs_vtimes",			/* 107 = obsolete vtimes */
	"old.freebsd32_sigvec",		/* 108 = old freebsd32_sigvec */
	"old.freebsd32_sigblock",		/* 109 = old freebsd32_sigblock */
	"old.freebsd32_sigsetmask",		/* 110 = old freebsd32_sigsetmask */
	"old.freebsd32_sigsuspend",		/* 111 = old freebsd32_sigsuspend */
	"old.freebsd32_sigstack",		/* 112 = old freebsd32_sigstack */
	"obs_orecvmsg",			/* 113 = obsolete orecvmsg */
	"obs_osendmsg",			/* 114 = obsolete osendmsg */
	"obs_vtrace",			/* 115 = obsolete vtrace */
	"freebsd32_gettimeofday",			/* 116 = freebsd32_gettimeofday */
	"freebsd32_getrusage",			/* 117 = freebsd32_getrusage */
	"getsockopt",			/* 118 = getsockopt */
	"#119",			/* 119 = resuba */
	"freebsd32_readv",			/* 120 = freebsd32_readv */
	"freebsd32_writev",			/* 121 = freebsd32_writev */
	"freebsd32_settimeofday",			/* 122 = freebsd32_settimeofday */
	"fchown",			/* 123 = fchown */
	"fchmod",			/* 124 = fchmod */
	"obs_orecvfrom",			/* 125 = obsolete orecvfrom */
	"setreuid",			/* 126 = setreuid */
	"setregid",			/* 127 = setregid */
	"rename",			/* 128 = rename */
	"obs_otruncate",			/* 129 = obsolete otruncate */
	"obs_ftruncate",			/* 130 = obsolete ftruncate */
	"flock",			/* 131 = flock */
	"mkfifo",			/* 132 = mkfifo */
	"sendto",			/* 133 = sendto */
	"shutdown",			/* 134 = shutdown */
	"socketpair",			/* 135 = socketpair */
	"mkdir",			/* 136 = mkdir */
	"rmdir",			/* 137 = rmdir */
	"freebsd32_utimes",			/* 138 = freebsd32_utimes */
	"obs_4.2",			/* 139 = obsolete 4.2 sigreturn */
	"freebsd32_adjtime",			/* 140 = freebsd32_adjtime */
	"obs_ogetpeername",			/* 141 = obsolete ogetpeername */
	"obs_ogethostid",			/* 142 = obsolete ogethostid */
	"obs_sethostid",			/* 143 = obsolete sethostid */
	"obs_getrlimit",			/* 144 = obsolete getrlimit */
	"obs_setrlimit",			/* 145 = obsolete setrlimit */
	"obs_killpg",			/* 146 = obsolete killpg */
	"setsid",			/* 147 = setsid */
	"quotactl",			/* 148 = quotactl */
	"obs_oquota",			/* 149 = obsolete oquota */
	"obs_ogetsockname",			/* 150 = obsolete ogetsockname */
	"#151",			/* 151 = sem_lock */
	"#152",			/* 152 = sem_wakeup */
	"#153",			/* 153 = asyncdaemon */
	"#154",			/* 154 = nosys */
	"#155",			/* 155 = nfssvc */
	"obs_ogetdirentries",			/* 156 = obsolete ogetdirentries */
	"old.freebsd32_statfs",		/* 157 = old freebsd32_statfs */
	"old.freebsd32_fstatfs",		/* 158 = old freebsd32_fstatfs */
	"#159",			/* 159 = nosys */
	"#160",			/* 160 = nosys */
	"getfh",			/* 161 = getfh */
	"getdomainname",			/* 162 = getdomainname */
	"setdomainname",			/* 163 = setdomainname */
	"uname",			/* 164 = uname */
	"sysarch",			/* 165 = sysarch */
	"rtprio",			/* 166 = rtprio */
	"#167",			/* 167 = nosys */
	"#168",			/* 168 = nosys */
	"freebsd32_semsys",			/* 169 = freebsd32_semsys */
	"freebsd32_msgsys",			/* 170 = freebsd32_msgsys */
	"freebsd32_shmsys",			/* 171 = freebsd32_shmsys */
	"#172",			/* 172 = nosys */
	"freebsd32_pread",			/* 173 = freebsd32_pread */
	"freebsd32_pwrite",			/* 174 = freebsd32_pwrite */
	"#175",			/* 175 = nosys */
	"ntp_adjtime",			/* 176 = ntp_adjtime */
	"#177",			/* 177 = sfork */
	"#178",			/* 178 = getdescriptor */
	"#179",			/* 179 = setdescriptor */
	"#180",			/* 180 = nosys */
	"setgid",			/* 181 = setgid */
	"setegid",			/* 182 = setegid */
	"seteuid",			/* 183 = seteuid */
	"#184",			/* 184 = lfs_bmapv */
	"#185",			/* 185 = lfs_markv */
	"#186",			/* 186 = lfs_segclean */
	"#187",			/* 187 = lfs_segwait */
	"freebsd32_stat",			/* 188 = freebsd32_stat */
	"freebsd32_fstat",			/* 189 = freebsd32_fstat */
	"freebsd32_lstat",			/* 190 = freebsd32_lstat */
	"pathconf",			/* 191 = pathconf */
	"fpathconf",			/* 192 = fpathconf */
	"#193",			/* 193 = nosys */
	"getrlimit",			/* 194 = getrlimit */
	"setrlimit",			/* 195 = setrlimit */
	"getdirentries",			/* 196 = getdirentries */
	"freebsd32_mmap",			/* 197 = freebsd32_mmap */
	"__syscall",			/* 198 = __syscall */
	"freebsd32_lseek",			/* 199 = freebsd32_lseek */
	"freebsd32_truncate",			/* 200 = freebsd32_truncate */
	"freebsd32_ftruncate",			/* 201 = freebsd32_ftruncate */
	"freebsd32_sysctl",			/* 202 = freebsd32_sysctl */
	"mlock",			/* 203 = mlock */
	"munlock",			/* 204 = munlock */
	"undelete",			/* 205 = undelete */
	"freebsd32_futimes",			/* 206 = freebsd32_futimes */
	"getpgid",			/* 207 = getpgid */
	"#208",			/* 208 = newreboot */
	"poll",			/* 209 = poll */
	"#210",			/* 210 =  */
	"#211",			/* 211 =  */
	"#212",			/* 212 =  */
	"#213",			/* 213 =  */
	"#214",			/* 214 =  */
	"#215",			/* 215 =  */
	"#216",			/* 216 =  */
	"#217",			/* 217 =  */
	"#218",			/* 218 =  */
	"#219",			/* 219 =  */
	"__semctl",			/* 220 = __semctl */
	"semget",			/* 221 = semget */
	"semop",			/* 222 = semop */
	"#223",			/* 223 = semconfig */
	"msgctl",			/* 224 = msgctl */
	"msgget",			/* 225 = msgget */
	"msgsnd",			/* 226 = msgsnd */
	"msgrcv",			/* 227 = msgrcv */
	"shmat",			/* 228 = shmat */
	"shmctl",			/* 229 = shmctl */
	"shmdt",			/* 230 = shmdt */
	"shmget",			/* 231 = shmget */
	"freebsd32_clock_gettime",			/* 232 = freebsd32_clock_gettime */
	"freebsd32_clock_settime",			/* 233 = freebsd32_clock_settime */
	"freebsd32_clock_getres",			/* 234 = freebsd32_clock_getres */
	"#235",			/* 235 = timer_create */
	"#236",			/* 236 = timer_delete */
	"#237",			/* 237 = timer_settime */
	"#238",			/* 238 = timer_gettime */
	"#239",			/* 239 = timer_getoverrun */
	"freebsd32_nanosleep",			/* 240 = freebsd32_nanosleep */
	"#241",			/* 241 = nosys */
	"#242",			/* 242 = nosys */
	"#243",			/* 243 = nosys */
	"#244",			/* 244 = nosys */
	"#245",			/* 245 = nosys */
	"#246",			/* 246 = nosys */
	"#247",			/* 247 = nosys */
	"#248",			/* 248 = ntp_gettime */
	"#249",			/* 249 = nosys */
	"minherit",			/* 250 = minherit */
	"rfork",			/* 251 = rfork */
	"openbsd_poll",			/* 252 = openbsd_poll */
	"issetugid",			/* 253 = issetugid */
	"lchown",			/* 254 = lchown */
	"#255",			/* 255 = nosys */
	"#256",			/* 256 = nosys */
	"#257",			/* 257 = nosys */
	"#258",			/* 258 = nosys */
	"#259",			/* 259 = nosys */
	"#260",			/* 260 = nosys */
	"#261",			/* 261 = nosys */
	"#262",			/* 262 = nosys */
	"#263",			/* 263 = nosys */
	"#264",			/* 264 = nosys */
	"#265",			/* 265 = nosys */
	"#266",			/* 266 = nosys */
	"#267",			/* 267 = nosys */
	"#268",			/* 268 = nosys */
	"#269",			/* 269 = nosys */
	"#270",			/* 270 = nosys */
	"#271",			/* 271 = nosys */
	"getdents",			/* 272 = getdents */
	"#273",			/* 273 = nosys */
	"lchmod",			/* 274 = lchmod */
	"netbsd_lchown",			/* 275 = netbsd_lchown */
	"freebsd32_lutimes",			/* 276 = freebsd32_lutimes */
	"netbsd_msync",			/* 277 = netbsd_msync */
	"nstat",			/* 278 = nstat */
	"nfstat",			/* 279 = nfstat */
	"nlstat",			/* 280 = nlstat */
	"#281",			/* 281 = nosys */
	"#282",			/* 282 = nosys */
	"#283",			/* 283 = nosys */
	"#284",			/* 284 = nosys */
	"#285",			/* 285 = nosys */
	"#286",			/* 286 = nosys */
	"#287",			/* 287 = nosys */
	"#288",			/* 288 = nosys */
	"freebsd32_preadv",			/* 289 = freebsd32_preadv */
	"freebsd32_pwritev",			/* 290 = freebsd32_pwritev */
	"#291",			/* 291 = nosys */
	"#292",			/* 292 = nosys */
	"#293",			/* 293 = nosys */
	"#294",			/* 294 = nosys */
	"#295",			/* 295 = nosys */
	"#296",			/* 296 = nosys */
	"old.freebsd32_fhstatfs",		/* 297 = old freebsd32_fhstatfs */
	"fhopen",			/* 298 = fhopen */
	"fhstat",			/* 299 = fhstat */
	"modnext",			/* 300 = modnext */
	"freebsd32_modstat",			/* 301 = freebsd32_modstat */
	"modfnext",			/* 302 = modfnext */
	"modfind",			/* 303 = modfind */
	"kldload",			/* 304 = kldload */
	"kldunload",			/* 305 = kldunload */
	"kldfind",			/* 306 = kldfind */
	"kldnext",			/* 307 = kldnext */
	"kldstat",			/* 308 = kldstat */
	"kldfirstmod",			/* 309 = kldfirstmod */
	"getsid",			/* 310 = getsid */
	"setresuid",			/* 311 = setresuid */
	"setresgid",			/* 312 = setresgid */
	"obs_signanosleep",			/* 313 = obsolete signanosleep */
	"#314",			/* 314 = aio_return */
	"#315",			/* 315 = aio_suspend */
	"#316",			/* 316 = aio_cancel */
	"#317",			/* 317 = aio_error */
	"#318",			/* 318 = aio_read */
	"#319",			/* 319 = aio_write */
	"#320",			/* 320 = lio_listio */
	"yield",			/* 321 = yield */
	"obs_thr_sleep",			/* 322 = obsolete thr_sleep */
	"obs_thr_wakeup",			/* 323 = obsolete thr_wakeup */
	"mlockall",			/* 324 = mlockall */
	"munlockall",			/* 325 = munlockall */
	"__getcwd",			/* 326 = __getcwd */
	"sched_setparam",			/* 327 = sched_setparam */
	"sched_getparam",			/* 328 = sched_getparam */
	"sched_setscheduler",			/* 329 = sched_setscheduler */
	"sched_getscheduler",			/* 330 = sched_getscheduler */
	"sched_yield",			/* 331 = sched_yield */
	"sched_get_priority_max",			/* 332 = sched_get_priority_max */
	"sched_get_priority_min",			/* 333 = sched_get_priority_min */
	"sched_rr_get_interval",			/* 334 = sched_rr_get_interval */
	"utrace",			/* 335 = utrace */
	"old.freebsd32_sendfile",		/* 336 = old freebsd32_sendfile */
	"kldsym",			/* 337 = kldsym */
	"jail",			/* 338 = jail */
	"#339",			/* 339 = pioctl */
	"sigprocmask",			/* 340 = sigprocmask */
	"sigsuspend",			/* 341 = sigsuspend */
	"old.freebsd32_sigaction",		/* 342 = old freebsd32_sigaction */
	"sigpending",			/* 343 = sigpending */
	"old.freebsd32_sigreturn",		/* 344 = old freebsd32_sigreturn */
	"#345",			/* 345 = sigtimedwait */
	"#346",			/* 346 = sigwaitinfo */
	"__acl_get_file",			/* 347 = __acl_get_file */
	"__acl_set_file",			/* 348 = __acl_set_file */
	"__acl_get_fd",			/* 349 = __acl_get_fd */
	"__acl_set_fd",			/* 350 = __acl_set_fd */
	"__acl_delete_file",			/* 351 = __acl_delete_file */
	"__acl_delete_fd",			/* 352 = __acl_delete_fd */
	"__acl_aclcheck_file",			/* 353 = __acl_aclcheck_file */
	"__acl_aclcheck_fd",			/* 354 = __acl_aclcheck_fd */
	"extattrctl",			/* 355 = extattrctl */
	"extattr_set_file",			/* 356 = extattr_set_file */
	"extattr_get_file",			/* 357 = extattr_get_file */
	"extattr_delete_file",			/* 358 = extattr_delete_file */
	"#359",			/* 359 = aio_waitcomplete */
	"getresuid",			/* 360 = getresuid */
	"getresgid",			/* 361 = getresgid */
	"kqueue",			/* 362 = kqueue */
	"freebsd32_kevent",			/* 363 = freebsd32_kevent */
	"#364",			/* 364 = __cap_get_proc */
	"#365",			/* 365 = __cap_set_proc */
	"#366",			/* 366 = __cap_get_fd */
	"#367",			/* 367 = __cap_get_file */
	"#368",			/* 368 = __cap_set_fd */
	"#369",			/* 369 = __cap_set_file */
	"#370",			/* 370 = lkmressys */
	"extattr_set_fd",			/* 371 = extattr_set_fd */
	"extattr_get_fd",			/* 372 = extattr_get_fd */
	"extattr_delete_fd",			/* 373 = extattr_delete_fd */
	"__setugid",			/* 374 = __setugid */
	"#375",			/* 375 = nfsclnt */
	"eaccess",			/* 376 = eaccess */
	"#377",			/* 377 = afs_syscall */
	"nmount",			/* 378 = nmount */
	"kse_exit",			/* 379 = kse_exit */
	"kse_wakeup",			/* 380 = kse_wakeup */
	"kse_create",			/* 381 = kse_create */
	"kse_thr_interrupt",			/* 382 = kse_thr_interrupt */
	"kse_release",			/* 383 = kse_release */
	"#384",			/* 384 = __mac_get_proc */
	"#385",			/* 385 = __mac_set_proc */
	"#386",			/* 386 = __mac_get_fd */
	"#387",			/* 387 = __mac_get_file */
	"#388",			/* 388 = __mac_set_fd */
	"#389",			/* 389 = __mac_set_file */
	"kenv",			/* 390 = kenv */
	"lchflags",			/* 391 = lchflags */
	"uuidgen",			/* 392 = uuidgen */
	"freebsd32_sendfile",			/* 393 = freebsd32_sendfile */
	"#394",			/* 394 = mac_syscall */
	"getfsstat",			/* 395 = getfsstat */
	"statfs",			/* 396 = statfs */
	"fstatfs",			/* 397 = fstatfs */
	"fhstatfs",			/* 398 = fhstatfs */
	"#399",			/* 399 = nosys */
	"#400",			/* 400 = ksem_close */
	"#401",			/* 401 = ksem_post */
	"#402",			/* 402 = ksem_wait */
	"#403",			/* 403 = ksem_trywait */
	"#404",			/* 404 = ksem_init */
	"#405",			/* 405 = ksem_open */
	"#406",			/* 406 = ksem_unlink */
	"#407",			/* 407 = ksem_getvalue */
	"#408",			/* 408 = ksem_destroy */
	"#409",			/* 409 = __mac_get_pid */
	"#410",			/* 410 = __mac_get_link */
	"#411",			/* 411 = __mac_set_link */
	"#412",			/* 412 = extattr_set_link */
	"#413",			/* 413 = extattr_get_link */
	"#414",			/* 414 = extattr_delete_link */
	"#415",			/* 415 = __mac_execve */
	"freebsd32_sigaction",			/* 416 = freebsd32_sigaction */
	"freebsd32_sigreturn",			/* 417 = freebsd32_sigreturn */
	"#418",			/* 418 = __xstat */
	"#419",			/* 419 = __xfstat */
	"#420",			/* 420 = __xlstat */
	"freebsd32_getcontext",			/* 421 = freebsd32_getcontext */
	"freebsd32_setcontext",			/* 422 = freebsd32_setcontext */
	"freebsd32_swapcontext",			/* 423 = freebsd32_swapcontext */
	"#424",			/* 424 = swapoff */
	"#425",			/* 425 = __acl_get_link */
	"#426",			/* 426 = __acl_set_link */
	"#427",			/* 427 = __acl_delete_link */
	"#428",			/* 428 = __acl_aclcheck_link */
	"#429",			/* 429 = sigwait */
	"thr_create",			/* 430 = thr_create */
	"thr_exit",			/* 431 = thr_exit */
	"thr_self",			/* 432 = thr_self */
	"thr_kill",			/* 433 = thr_kill */
	"_umtx_lock",			/* 434 = _umtx_lock */
	"_umtx_unlock",			/* 435 = _umtx_unlock */
	"jail_attach",			/* 436 = jail_attach */
	"#437",			/* 437 = extattr_list_fd */
	"#438",			/* 438 = extattr_list_file */
	"#439",			/* 439 = extattr_list_link */
	"#440",			/* 440 = kse_switchin */
	"#441",			/* 441 = ksem_timedwait */
	"thr_suspend",			/* 442 = thr_suspend */
	"thr_wake",			/* 443 = thr_wake */
	"kldunloadf",			/* 444 = kldunloadf */
	"#445",			/* 445 = audit */
	"#446",			/* 446 = auditon */
	"#447",			/* 447 = getauid */
	"#448",			/* 448 = setauid */
	"#449",			/* 449 = getaudit */
	"#450",			/* 450 = setaudit */
	"#451",			/* 451 = getaudit_addr */
	"#452",			/* 452 = setaudit_addr */
	"#453",			/* 453 = auditctl */
	"#454",			/* 454 = _umtx_op */
	"#455",			/* 455 = thr_new */
	"#456",			/* 456 = sigqueue */
	"#457",			/* 457 = mq_open */
	"#458",			/* 458 = mq_setattr */
	"#459",			/* 459 = mq_timedreceive */
	"#460",			/* 460 = mq_timedsend */
	"#461",			/* 461 = mq_notify */
	"#462",			/* 462 = mq_unlink */
	"abort2",			/* 463 = abort2 */
};
