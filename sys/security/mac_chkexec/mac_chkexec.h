/*-
 * Copyright (c) 2005 Christian S.J. Peron
 * All rights reserved.
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
#ifndef	MAC_CHKEXEC_H_
#define	MAC_CHKEXEC_H_ 

#define MAC_VCSUM_MD5		0x00000001
#define MAC_VCSUM_SHA1		0x00000002
#define MAC_CHKEXEC_ATTRN	EXTATTR_NAMESPACE_SYSTEM
#define MAC_CHKEXEC		"chkexec"
#define MAC_CHKEXEC_DEP		"chkexec_depend"
#define	SHA1_HASH_SIZE	20
#define	MD5_HASH_SIZE	16
#define	MAXCSUMSIZE	32

#ifdef _KERNEL
struct vcache {
        RB_ENTRY(vcache) glue;
        u_long           fileid;
        u_char           digest[MAXCSUMSIZE];
};

struct vcache_fs {
	RB_HEAD(btree, vcache) btree;
	struct mtx btree_mtx;
	dev_t fsid;
	TAILQ_ENTRY(vcache_fs) glue;
};
#endif	/* _KERNEL */

struct mac_vcsum {
	u_char	vs_sum[32];	/* vnode checksum */
	int	vs_flags;
};

struct ucred;
struct vnode;
struct hash_algo {
	int	 (*crypto_hash)(struct vnode *, struct ucred *, u_char *);
        size_t	 hashsize;	/* size of message digest */
        int	 hashmask;	/* hash algorithm mask */
        char	*hashname;	/* name of hashing algorithm */
};
#endif	/* MAC_CHCKEXEC_H_ */
