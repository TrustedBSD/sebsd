/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
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

#ifndef _SEBSD_SYSCALLS_H_
#define	_SEBSD_SYSCALLS_H_

/*
 * TBD: Should we really try to line up with SELinux?
 */
#define	SEBSDCALL_LOAD_POLICY		7
#define	SEBSDCALL_GET_BOOLS	        8
#define	SEBSDCALL_GET_BOOL		9
#define	SEBSDCALL_SET_BOOL		10
#define	SEBSDCALL_COMMIT_BOOLS		11

#define	SEBSDCALL_NUM			7

/* Structure definitions for compute_av call. */
struct security_query {
	char		*scontext;
	char		*tcontext;
	u_int16_t	 tclass;
	u_int32_t	 requested;
};

struct security_response {
	u_int32_t	 allowed;
	u_int32_t	 decided;
	u_int32_t	 auditallow;
	u_int32_t	 auditdeny;
	u_int32_t	 notify;
	u_int32_t	 seqno;
};

struct sebsd_get_bools {
	int	 len;
	char	*out;
};

struct lp_args {
	void	*data;
	size_t	 len;
};

#endif /* _SEBSD_SYSCALLS_H_ */
