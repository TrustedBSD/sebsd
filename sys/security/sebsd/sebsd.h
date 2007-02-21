/*-
 * Copyright (c) 2002 Networks Associates Technologies, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by NAI Labs, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
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

#ifndef _SYS_SECURITY_SEBSD_H
#define _SYS_SECURITY_SEBSD_H

#define SELINUX_MAGIC 0xf97cff8c
#define	SEBSD_MAC_EXTATTR_NAME		"sebsd"
#define	SEBSD_MAC_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM

extern int	avc_debug_always_allow;

#ifndef _M_SEBSD_DEF
MALLOC_DECLARE(M_SEBSD);
#define	_M_SEBSD_DEF
#endif

#ifndef sebsd_malloc
#define	sebsd_malloc(s, t, f)	malloc(s, t, f)
#define	sebsd_free(a, t)	free(a, t)
#endif

extern int sebsd_verbose;

extern int	security_init(void);
extern int	sebsd_syscall(struct thread *td, int call, void *args);
extern int	thread_has_system(struct thread *td, u_int32_t perm);
extern int	thread_has_security(struct thread *td, u_int32_t perm);

#endif /* _SYS_SECURITY_SEBSD_H */
