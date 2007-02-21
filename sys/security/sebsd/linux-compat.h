/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
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

#ifndef _SYS_SECURITY_LINUX_COMPAT_H
#define _SYS_SECURITY_LINUX_COMPAT_H

/*
 * Try and convert some of the linux kernel routines to something that
 * works in FreeBSD.  Perhaps a bit dangerous, but the hope is that
 * diffs to the SELinux tree will be quite a bit smaller.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/libkern.h>

typedef u_int64_t u64;
typedef u_int64_t __le64;
typedef u_int32_t u32;
typedef u_int32_t __le32;
typedef u_int32_t __be32;
typedef u_int16_t u16;
typedef u_int16_t __le16;
typedef u_int16_t __be16;
typedef u_int8_t  u8;
typedef int	  gfp_t;


#define cpu_to_le16(a) htole16(a) 
#define cpu_to_le32(a) htole32(a) 
#define cpu_to_le64(a) htole64(a) 
#define le16_to_cpu(a) le16toh(a) 
#define le32_to_cpu(a) le32toh(a) 
#define le64_to_cpu(a) le64toh(a) 

/* branch prediction macros, uses a GCC extension. */
#define likely(exp)	__builtin_expect(!!(exp), 1)
#define unlikely(exp)	__builtin_expect(!!(exp), 0)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define __init

/* kmalloc */
#define GFP_ATOMIC  M_NOWAIT
#define GFP_KERNEL  M_NOWAIT
#define kcalloc(nmemb, size, flags) malloc(nmemb * size, M_SEBSD, flags | M_ZERO)
#define kmalloc(size,flags)	malloc(size, M_SEBSD, flags)
#define kzalloc(size,flags)	malloc(size, M_SEBSD, flags | M_ZERO)
#define kfree(v)		free(v, M_SEBSD)
#define __get_free_page(flags)	malloc(4096, M_SEBSD, flags) /* XXX need page size */

/* also defined in sebsd.h */
#ifndef sebsd_malloc
#define	sebsd_malloc(s, t, f)	malloc(s, t, f)
#define	sebsd_free(a, t)	free(a, t)
#endif

#include <sys/malloc.h>
#ifndef _M_SEBSD_DEF
MALLOC_DECLARE(M_SEBSD);
#define _M_SEBSD_DEF
#endif

static inline char *
kstrdup(const char *str, int mflag)
{
	char *newstr;
	size_t len = strlen(str) + 1;

	newstr = malloc(len, M_SEBSD, mflag);
	if (newstr != NULL)
		memcpy(newstr, str, len);
	return (newstr);
}

/* FreeBSD has no spinlock, use mutex instead */
#define spinlock_t struct mtx
#define spin_lock_irqsave(m,flags) mtx_lock(m)
#define spin_unlock_irqrestore(m,flags) mtx_unlock(m)

/* emulate linux audit support */
extern struct mtx avc_log_lock;
struct audit_buffer;
struct audit_buffer *_audit_log_start(int);
void audit_log_end(struct audit_buffer *);
void audit_log_format(struct audit_buffer *, const char *, ...);
void audit_log_untrustedstring(struct audit_buffer *, const char *);
#define audit_log_start(ac, mf, af) _audit_log_start(mf)
#define audit_log(ac, mf, af, ...) do {					\
	mtx_lock(&avc_log_lock);					\
	printf(__VA_ARGS__);						\
	printf("\n");							\
	mtx_unlock(&avc_log_lock);					\
} while (0)
#define sebsd_log(fmt, ...)	printf(fmt "\n", __VA_ARGS__)

/* we don't enable the selinux netlbl support */
#define selinux_netlbl_cache_invalidate()

/*
 * Atomic integer operations, Linux style
 */
typedef unsigned int		atomic_t;
#define	atomic_inc(p)		atomic_add_acq_32(p, 1)
#define	atomic_inc_return(p)	atomic_fetchadd_32(p, 1) 
#define	atomic_dec(p)		atomic_subtract_acq_32(p, 1)
#define	atomic_dec_and_test(p)	(atomic_fetchadd_acq_32(p, -1) == 0)
#define	atomic_read(p)		atomic_load_acq_32(p)
#define	atomic_set(p, v)	atomic_store_rel_32(p, v)

/* FreeBSD has index() not strchr() in the kernel. */
#define	strchr(s, c)			index(s, c)

#define BUG() printf("BUG: %s:%d", __FILE__, __LINE__)
#define BUG_ON(x) do { if (x) BUG(); } while(0)

#define wmb() 

/* printk */
#define printk printf
#define KERN_WARNING "warning: "
#define KERN_INFO
#define KERN_ERR     "error: "

#endif /* _SYS_SECURITY_LINUX_COMPAT_H */
