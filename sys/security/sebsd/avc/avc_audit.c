/*-
 * Copyright (c) 2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed by SPARTA ISSO under SPAWAR contract
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
 */

#include <sys/param.h>
#include <sys/sbuf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <vm/uma.h>

#include <machine/stdarg.h>

#include <security/sebsd/linux-compat.h>
#include <security/sebsd/sebsd.h>
#include <security/sebsd/avc/avc.h>

/*
 * Emulate Linux audit API.
 * In the future we may wish to use the BSD audit support instead.
 * TBD: use a freelist so we don't have to mallc/free so much.
 */

struct mtx avc_log_lock;
MTX_SYSINIT(avc_log_lock, &avc_log_lock, "SEBSD message lock", MTX_DEF); 

struct audit_buffer {
	struct sbuf sbuf;
	char buf[1024];
};

static uma_zone_t avc_audit_zone;		/* audit buffer zone */
static struct audit_buffer *spare_buf;		/* spare buffer */

void
avc_audit_init(void)
{

	avc_audit_zone = uma_zcreate("avc_audit", sizeof(struct audit_buffer),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	spare_buf = uma_zalloc(avc_audit_zone, M_WAITOK);
}

struct audit_buffer *
_audit_log_start(int flag)
{
	struct audit_buffer *ab = spare_buf;

	/* Use a free buffer if available, else alloc a new one. */
	if (ab != NULL &&
	    atomic_cmpset_ptr((intptr_t *)&spare_buf, (intptr_t)ab, 0) == 0)
		ab = NULL;
	if (ab == NULL) {
		ab = uma_zalloc(avc_audit_zone, flag);
		if (ab == NULL) {
			printf("%s: unable to allocate audit buffer\n",
			    __func__);
			return (NULL);
		}
	}
	sbuf_new(&ab->sbuf, ab->buf, sizeof(ab->buf), SBUF_FIXEDLEN);
	return (ab);
}

void
audit_log_end(struct audit_buffer *ab)
{

	sbuf_finish(&ab->sbuf);
	mtx_lock(&avc_log_lock);
	printf("\n%s\n", sbuf_data(&ab->sbuf));
	mtx_unlock(&avc_log_lock);
	/* Always keep a free buffer around. */
	if (spare_buf != NULL ||
	    atomic_cmpset_ptr((intptr_t *)&spare_buf, 0, (intptr_t)ab) == 0)
		uma_zfree(avc_audit_zone, ab);
}

void
audit_log_format(struct audit_buffer *ab, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbuf_vprintf(&ab->sbuf, fmt, ap);
	va_end(ap);
}

void
audit_log_untrustedstring(struct audit_buffer *ab, const char *s)
{

	sbuf_cat(&ab->sbuf, s);	/* XXX - wants vis(3) support */
}
