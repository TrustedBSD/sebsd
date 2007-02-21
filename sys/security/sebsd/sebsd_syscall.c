/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * Copyright (c) 2005 SPARTA, Inc.
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
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>

#include <security/sebsd/sebsd.h>
#include <security/sebsd/sebsd_syscalls.h>
#include <security/sebsd/linux-compat.h>
#include <security/sebsd/avc/avc.h>
#include <security/sebsd/ss/services.h>

static int
sys_load_policy(struct thread *td, void *data, size_t len)
{
	int rc;
	void *kdata;
	
	rc = thread_has_security(td, SECURITY__LOAD_POLICY);
	if (rc)
		return (rc);

	kdata = sebsd_malloc(len, M_SEBSD, M_WAITOK);
	rc = copyin(data, kdata, len);
	if (rc)
		return (rc);

	rc = security_load_policy(kdata, len);
	sebsd_free(kdata, M_SEBSD);

	return (rc);
}

static int
sebsd_get_bools(struct thread *td, struct sebsd_get_bools *gb)
{
	char *out;
	int error;

	if (gb->out)
		out = sebsd_malloc(gb->len, M_SEBSD, M_WAITOK);
	else
		out = NULL;
	error = security_get_bool_string(&gb->len, out);
	if (out != NULL && error == 0)
		error = copyout(out, gb->out, gb->len);
	if (out != NULL)
		sebsd_free(out, M_SEBSD);
	return (error);
}

int
sebsd_syscall(struct thread *td, int call, void *args)
{
	struct lp_args p;
	struct sebsd_get_bools gb;
	int active, error, pending;
	char str[128], *strp;

	error = EINVAL;
	switch (call) {
	case SEBSDCALL_LOAD_POLICY:
		if (copyin(args, &p, sizeof(struct lp_args)))
			return (EFAULT);
		error = sys_load_policy(td, p.data, p.len);
		break;

	case SEBSDCALL_GET_BOOLS:
		if (copyin(args, &gb, sizeof(struct sebsd_get_bools)))
			return (EFAULT);
		error = sebsd_get_bools(td, &gb);
		if (copyout(&gb, args, sizeof(struct sebsd_get_bools)))
			return (EFAULT);
		break;

	case SEBSDCALL_GET_BOOL:
		error = copyinstr(args, str, 128, NULL);
		if (error)
			return (error);
		security_get_bool(str, &active, &pending);
		*td->td_retval = active | (pending << 1);
		return (0);

	case SEBSDCALL_SET_BOOL:
		error = thread_has_security(td, SECURITY__SETBOOL);
		if (error)
			return (error);

		if (copyin(args, &p, sizeof(struct lp_args)))
			return (EFAULT);
		strp = sebsd_malloc(p.len, M_SEBSD, M_WAITOK);
		if (!str)
			return (ENOMEM);
		if (copyin(p.data, strp, p.len)) {
			sebsd_free(str, M_SEBSD);
			return (EFAULT);
		}

		strp[p.len-1] = 0;
		error = security_set_bool(str+1, strp[0]-'0');
		sebsd_free(strp, M_SEBSD);
		break;

	case SEBSDCALL_COMMIT_BOOLS:
		error = thread_has_security(td, SECURITY__SETBOOL);
		if (error)
			return (error);

		return (security_commit_pending_bools());

	default:
		error = EINVAL;
		break;
	}

	return (error);
}
