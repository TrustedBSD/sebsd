/*
 * Copyright (c) 2005 Christian S.J. Peron <csjp@FreeBSD.org>
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
#include <sys/types.h>
#include <sys/param.h>
#include <sys/acl.h>
#include <sys/conf.h>
#include <sys/ktr.h>
#include <sys/kdb.h>
#include <sys/extattr.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mman.h>
#include <sys/mac.h>
#include <sys/md5.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/sx.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <fs/devfs/devfs.h>

#include <net/bpfdesc.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>

#include <vm/vm.h>

#include <sys/mac_policy.h>
#include <security/mac_chkexec/mac_chkexec.h>

#include <crypto/sha1.h>

/*
 * Prototypes
 */
static int	 mac_chkexec_calc_vnode_md5(struct vnode *,
		     struct ucred *, u_char *);
static int	 mac_chkexec_calc_vnode_sha1(struct vnode *,
		     struct ucred *, u_char *);
static struct hash_algo
		*mac_chkexec_get_algo(void);
static int	 mac_chkexec_get_vcsum(struct vnode *,
		     struct mac_vcsum *);
static int	 mac_chkexec_set_vcsum(struct vnode *,
		     struct mac_vcsum *);
static int	 mac_chkexec_check(struct vnode *, struct ucred *);
static int	 mac_chkexec_check_vnode_exec(struct ucred *,
		     struct vnode *, struct label *,
		     struct image_params *, struct label *);
static int	 mac_chkexec_check_vnode_mmap(struct ucred *,
		     struct vnode *, struct label *, int, int);
static int	 mac_chkexec_check_kld_load(struct ucred *,
		     struct vnode *, struct label *);
static int	 mac_chkexec_vpcmp(struct vcache *, struct vcache *);

static MALLOC_DEFINE(M_CHKEXEC, "mac_chkexec", "TrustedBSD trusted exec");
SYSCTL_DECL(_security_mac);
static SYSCTL_NODE(_security_mac, OID_AUTO, chkexec, CTLFLAG_RW,
    0, "mac_chkexec policy controls");
static int mac_chkexec_enable = 1;
SYSCTL_INT(_security_mac_chkexec, OID_AUTO, enable,
    CTLFLAG_SECURE | CTLFLAG_RW,
    &mac_chkexec_enable, 0, "enable trusted exec");
static int mac_chkexec_enforce;
SYSCTL_INT(_security_mac_chkexec, OID_AUTO, enforce,
    CTLFLAG_SECURE | CTLFLAG_RW,
    &mac_chkexec_enforce, 0, "enforce trusted exec policy");
static int mac_chkexec_ignore_untagged;
SYSCTL_INT(_security_mac_chkexec, OID_AUTO, ignore_untagged,
    CTLFLAG_RW | CTLFLAG_SECURE,
    &mac_chkexec_ignore_untagged, 0, "");
static int mac_csums_calculated;
SYSCTL_INT(_security_mac_chkexec, OID_AUTO, csums_calculated,
    CTLFLAG_RD, &mac_csums_calculated, 0, "");
static SYSCTL_NODE(_security_mac_chkexec, OID_AUTO, cache,
    CTLFLAG_RW, 0, "cache control OIDs for mac_chkexec");
static int mac_chkexec_cache = 1;
SYSCTL_INT(_security_mac_chkexec_cache, OID_AUTO, enable,
    CTLFLAG_RW, &mac_chkexec_cache, 0, "");
static int mac_chkexec_cache_hits;
SYSCTL_INT(_security_mac_chkexec_cache, OID_AUTO, hits,
    CTLFLAG_RD, &mac_chkexec_cache_hits, 0, "");
static int cache_vec_alloc = 1024;
SYSCTL_INT(_security_mac_chkexec_cache, OID_AUTO, objmax,
    CTLFLAG_RW, &cache_vec_alloc, 0, "");
static int cache_vec_used;
SYSCTL_INT(_security_mac_chkexec_cache, OID_AUTO, objused,
    CTLFLAG_RD, &cache_vec_used, 0, "");
static int cache_invalidations;
SYSCTL_INT(_security_mac_chkexec_cache, OID_AUTO, invalidations,
    CTLFLAG_RD, &cache_invalidations, 0, "");
static char hashalgo[32] = "sha1";
SYSCTL_STRING(_security_mac_chkexec, OID_AUTO, algo,
    CTLFLAG_SECURE | CTLFLAG_RW,
    hashalgo, sizeof(hashalgo), "Current trusted exec algorithm");

static struct hash_algo ha_table[] = {
	{ mac_chkexec_calc_vnode_sha1, SHA1_HASH_SIZE, MAC_VCSUM_SHA1, "sha1" },
	{ mac_chkexec_calc_vnode_md5, MD5_HASH_SIZE, MAC_VCSUM_MD5, "md5" },
	{ NULL, 0, 0, NULL },
};

RB_PROTOTYPE(btree, vcache, glue, mac_chkexec_vpcmp);
RB_GENERATE(btree, vcache, glue, mac_chkexec_vpcmp);
TAILQ_HEAD(tailhead, vcache_fs) cache_head =
    TAILQ_HEAD_INITIALIZER(cache_head);
static struct mtx cache_mtx;
static uma_zone_t cache_zone;

/*
 * File ID comparison function. This function will be used
 * by the red/black binary search tree operations for caching.
 */
static int
mac_chkexec_vpcmp(struct vcache *vc1, struct vcache *vc2)
{

	if (vc1->fileid > vc2->fileid)
		return (1);
	if (vc1->fileid < vc2->fileid)
		return (-1);
	return (0);
}

static void
mac_chkexec_init(struct mac_policy_conf *conf)
{

	mtx_init(&cache_mtx, "lock for per device binary search trees",
	    NULL, MTX_DEF);
	TAILQ_INIT(&cache_head);
	cache_zone = uma_zcreate("MAC trusted exec cache zone",
	    sizeof(struct vcache), NULL, NULL, NULL,
	    NULL, UMA_ALIGN_PTR, 0);
	KASSERT(cache_zone != NULL, ("uma_zcreate returned NULL"));
}

static void
mac_chkexec_destroy(struct mac_policy_conf *conf)
{
	struct vcache *vcp, *next_vcp;
	struct vcache_fs *vfc, *vfc2;

	mtx_lock(&cache_mtx);
	TAILQ_FOREACH_SAFE(vfc, &cache_head, glue, vfc2) {
		mtx_lock(&vfc->btree_mtx);
		for (vcp = RB_MIN(btree, &vfc->btree); vcp != NULL;
		    vcp = next_vcp) {
			next_vcp = RB_NEXT(btree, &vfc->btree, vcp);
			RB_REMOVE(btree, &vfc->btree, vcp);
			uma_zfree(cache_zone, vcp);
			cache_vec_used--;
		}
		mtx_unlock(&vfc->btree_mtx);
		mtx_destroy(&vfc->btree_mtx);
		TAILQ_REMOVE(&cache_head, vfc, glue);
		free(vfc, M_CHKEXEC);
	}
	mtx_unlock(&cache_mtx);
	mtx_destroy(&cache_mtx);
	KASSERT(cache_zone != NULL, ("destroying null cache zone"));
	uma_zdestroy(cache_zone);
}

/* XXX reference counting should be used here */
/* Retrieve the cache associated with the filesystem ID stored in
 * the vnode. If a cache is not present, create one and return it.
 */
static struct vcache_fs *
mac_chkexec_get_fs_cache(struct vnode *vp)
{
	struct vcache_fs *vfc;
	struct vattr va, *vap;
	int error;
	struct thread *td = curthread;	/* XXX */

	ASSERT_VOP_LOCKED(vp, "mac_chkexec_get_fs_cache: no vlock held");
	vap = &va;
	error = VOP_GETATTR(vp, vap, td->td_ucred, td);
	if (error)
		return (NULL);
	mtx_lock(&cache_mtx);
	TAILQ_FOREACH(vfc, &cache_head, glue) 
		if (vfc->fsid == vap->va_fsid) {
			mtx_unlock(&cache_mtx);
			return (vfc);
		}
	mtx_unlock(&cache_mtx);
	vfc = malloc(sizeof(*vfc), M_CHKEXEC, M_WAITOK | M_ZERO);
	vfc->fsid = vap->va_fsid;
	mtx_init(&vfc->btree_mtx, "binary search tree lock",
	    NULL, MTX_DEF);
	RB_INIT(&vfc->btree);
	mtx_lock(&cache_mtx);
	TAILQ_INSERT_HEAD(&cache_head, vfc, glue);
	mtx_unlock(&cache_mtx);
	return (vfc);
}

/* Given a vnode and a cryptographic checksum, store it in the
 * per filesystem cache. Allow at most security.mac.chkexec.cache.objmax
 * elements to be cached.
 */
static void
mac_chkexec_cache_vcsum(struct vnode *vp, u_char *digest)
{
	struct vcache_fs *vfc;
	struct vcache *vcp;
	int error;
	struct vattr *vap, va;
	struct thread *td = curthread;

	ASSERT_VOP_LOCKED(vp, "no vlock held");
	if (!mac_chkexec_cache)
		return;
	if ((cache_vec_used + 1) > cache_vec_alloc)
		return;
	vfc = mac_chkexec_get_fs_cache(vp);
	if (vfc == NULL)
		return;
	vap = &va;
	error = VOP_GETATTR(vp, vap, td->td_ucred, td);
	if (error)
		return;
	vcp = uma_zalloc(cache_zone, M_WAITOK);
	vcp->fileid = vap->va_fileid;
	memcpy(vcp->digest, digest, MAXCSUMSIZE);
	mtx_lock(&cache_mtx);
	mtx_lock(&vfc->btree_mtx);
	if (RB_INSERT(btree, &vfc->btree, vcp) != NULL) {
		mtx_unlock(&vfc->btree_mtx);
		mtx_unlock(&cache_mtx);
		uma_zfree(cache_zone, vcp);
		CTR0(KTR_MAC, "mac_chkexec_cache_vcsum: element collision");
		return;
	}
	cache_vec_used++;
	mtx_unlock(&vfc->btree_mtx);
	mtx_unlock(&cache_mtx);
}

/* If an inode changes, we will want to invalidate the cache item
 * associated with it. Otherwise this could result in the execution
 * of a "used to be trusted, but not anymore" binary. We must be sure
 * that we hook any system calls which can modify the contents of the
 * file in anyway.
 */
static void
mac_chkexec_cache_invalidate(struct vnode *vp)
{
	struct vcache vc, *vcp;
	struct vcache_fs *vfc;
	struct vattr *vap, va;
	int error;
	struct thread *td = curthread;

	ASSERT_VOP_LOCKED(vp, "no vlock held");
	vfc = mac_chkexec_get_fs_cache(vp);
	if (vfc == NULL)
		return;
	vap = &va;
	error = VOP_GETATTR(vp, vap, td->td_ucred, td);
	if (error)
		return;
	vc.fileid = vap->va_fileid;
	mtx_lock(&vfc->btree_mtx);
	vcp = RB_FIND(btree, &vfc->btree, &vc);
	if (vcp == NULL) {
		mtx_unlock(&vfc->btree_mtx);
		return;
	}
	RB_REMOVE(btree, &vfc->btree, vcp);
	cache_vec_used--;
	cache_invalidations++;
	mtx_unlock(&vfc->btree_mtx);
	uma_zfree(cache_zone, vcp);
}

/* Given a vnode, retrieve the per filesystem cache and do a search
 * for the inode. If the item is not found, return NULL and let
 * the caller decide how to handle it, otherwise return a pointer
 * to the vcache item.
 */
static struct vcache *
mac_chkexec_cache_find(struct vnode *vp)
{
	struct vcache *vcp, vc;
	int error;
	struct vcache_fs *vfc;
	struct vattr va, *vap;
	struct thread *td = curthread;

	if (!mac_chkexec_cache)
		return (NULL);
	ASSERT_VOP_LOCKED(vp, "no vlock held");
	vap = &va;
	error = VOP_GETATTR(vp, &va, td->td_ucred, td);
	if (error)
		return (NULL);
	vfc = mac_chkexec_get_fs_cache(vp);
	if (vfc == NULL)
		return (NULL);
	vc.fileid = vap->va_fileid;
	mtx_lock(&vfc->btree_mtx);
	vcp = RB_FIND(btree, &vfc->btree, &vc);
	mtx_unlock(&vfc->btree_mtx);
	if (vcp)
		mac_chkexec_cache_hits++;
	return (vcp);
}

static struct hash_algo *
mac_chkexec_get_algo(void)
{
	struct hash_algo *ha;

	for (ha = &ha_table[0]; ha->hashname != NULL; ha++) {
		KASSERT(ha->hashsize <= MAXCSUMSIZE,
		    ("hashsize too big for buffer"));
		if (strcmp(hashalgo, ha->hashname) == 0)
			return (ha);
	}
	return (NULL);
}

static int
mac_chkexec_validate(struct mac_vcsum *vsum)
{

	switch (vsum->vs_flags) {
	case MAC_VCSUM_SHA1:
	case MAC_VCSUM_MD5:
		return (0);
	}
	return (EINVAL);
}

static int
mac_chkexec_get_vcsum(struct vnode *vp, struct mac_vcsum *vsum)
{
	struct thread *td;
	int error, attrlen;

	ASSERT_VOP_LOCKED(vp, "no vlock held");
	td = curthread;
	attrlen = sizeof(*vsum);
	error = vn_extattr_get(vp, IO_NODELOCKED, MAC_CHKEXEC_ATTRN,
	    MAC_CHKEXEC, &attrlen, (caddr_t)vsum, td);
	if (error)
		return (error);
	error = mac_chkexec_validate(vsum);
	if (error)
		return (error);
	if (attrlen != sizeof(*vsum)) {
		CTR1(KTR_MAC,
		    "mac_chkexec_get_vcsum: invalid attribute size %d",
		    attrlen);
		return (EPERM);
	}
	return (error);
}

static int
mac_chkexec_set_vcsum(struct vnode *vp, struct mac_vcsum *vsum)
{
	struct thread *td;
	int error;

	ASSERT_VOP_LOCKED(vp, "no vlock held");
	td = curthread;
	error = vn_extattr_set(vp, IO_NODELOCKED, MAC_CHKEXEC_ATTRN,
	    MAC_CHKEXEC, sizeof(*vsum), (caddr_t)vsum, td);
	return (error);
}

/* The checksum calculation code is reminiscent of the code found
 * in NetBSD "verified exec" with some additional error checking.
 */
static int
mac_chkexec_calc_vnode_md5(struct vnode *vp, struct ucred *cred,
    u_char *digest)
{
	struct thread *td;
	MD5_CTX	md5ctx;
	u_quad_t b;
	int error, count;
	int resid;
	struct vattr va;
	caddr_t bufobj;

	ASSERT_VOP_LOCKED(vp, "no vlock held");
	KASSERT(vp != NULL, ("mac_calc_vnode_md5: NULL vnode pointer"));
	td = curthread;
	error = VOP_GETATTR(vp, &va, cred, td);
	if (error)
		return (error);
	bufobj = malloc(PAGE_SIZE, M_CHKEXEC, M_WAITOK);
	MD5Init(&md5ctx);
	for (b = 0; b < va.va_size; b += PAGE_SIZE) {
		if ((PAGE_SIZE + b) > va.va_size)
			count = va.va_size - b;
		else
			count = PAGE_SIZE;
		error = vn_rdwr(UIO_READ, vp, bufobj, count, b,
		    UIO_SYSSPACE, IO_NODELOCKED, cred, NOCRED,
		    &resid, td);
		if (error) {
			free(bufobj, M_CHKEXEC);
			return (error);
		}
		if (resid != 0) {
			free(bufobj, M_CHKEXEC);
			return (EIO);
		}
		MD5Update(&md5ctx, bufobj, (u_int)count);
	}
	free(bufobj, M_CHKEXEC);
	/* Dont leak kernel memory */
	bzero(digest, MAXCSUMSIZE);
	MD5Final(digest, &md5ctx);
	mac_csums_calculated++;
	return (0);
}

static int
mac_chkexec_calc_vnode_sha1(struct vnode *vp, struct ucred *cred,
    u_char *digest)
{
	struct thread *td;
	SHA1_CTX sha1ctx;
	u_quad_t b;
	int error, count;
	int resid;
	struct vattr va;
	caddr_t bufobj;

	ASSERT_VOP_LOCKED(vp, "no vlock held");
	KASSERT(vp != NULL, ("mac_calc_vnode_sha1: NULL vnode pointer"));
	td = curthread;
	error = VOP_GETATTR(vp, &va, cred, td);
	if (error)
		return (error);
	bufobj = malloc(PAGE_SIZE, M_CHKEXEC, M_WAITOK);
	SHA1Init(&sha1ctx);
	for (b = 0; b < va.va_size; b += PAGE_SIZE) {
		if ((PAGE_SIZE + b) > va.va_size)
			count = va.va_size - b;
		else
			count = PAGE_SIZE;
		error = vn_rdwr(UIO_READ, vp, bufobj, count, b,
		    UIO_SYSSPACE, IO_NODELOCKED, cred, NOCRED,
		    &resid, td);
		if (error) {
			free(bufobj, M_CHKEXEC);
			return (error);
		}
		if (resid != 0) {
			free(bufobj, M_CHKEXEC);
			return (EIO);
		}
		SHA1Update(&sha1ctx, bufobj, (u_int)count);
	}
	free(bufobj, M_CHKEXEC);
	/* Dont leak kernel memory */
	bzero(digest, MAXCSUMSIZE);
	SHA1Final(digest, &sha1ctx);
	mac_csums_calculated++;
	return (0);
}

/* XXX we need to break circular dependencies here!! */
static int
mac_chkexec_check_depends(struct vnode *vp, struct ucred *cred)
{
	struct nameidata nd;
	char *depends, *ap;
	int vfslocked, alen, error;
	size_t ealen;

	ASSERT_VOP_LOCKED(vp, "no vlock held");
	error = VOP_GETEXTATTR(vp, MAC_CHKEXEC_ATTRN, MAC_CHKEXEC_DEP,
	    NULL, &ealen, NOCRED, curthread);
	if (error != 0 && error == ENOATTR)
		return (0);
	else if (error)
		return (error);
	/* XXX why are'nt extended attribute size specification types between
	 * VOP_GETEXTATTR and vn_extattr_get the same?
	 */
	alen = ealen;
	depends = malloc(alen + 1, M_CHKEXEC, M_WAITOK | M_ZERO);
	error = vn_extattr_get(vp, IO_NODELOCKED, MAC_CHKEXEC_ATTRN,
	    MAC_CHKEXEC_DEP, &alen, depends, curthread);
	if (error) {
		free(depends, M_CHKEXEC);
		return (error);
	}
	for (; (ap = strsep(&depends, ":")) != NULL && error == 0;) {
		if (strlen(ap) == 0)
			continue;
		NDINIT(&nd, LOOKUP, MPSAFE | LOCKLEAF | FOLLOW, UIO_SYSSPACE,
		    ap, curthread);
		if ((error = namei(&nd)) != 0) {
			free(depends, M_CHKEXEC);
			return (error);
		}
		vfslocked = NDHASGIANT(&nd);
		error = mac_chkexec_check(nd.ni_vp, cred);
		NDFREE(&nd, NDF_ONLY_PNBUF);
		vput(nd.ni_vp);
		VFS_UNLOCK_GIANT(vfslocked);
	}
	free(depends, M_CHKEXEC);
	return (error);
}

static int
mac_chkexec_check(struct vnode *vp, struct ucred *cred)
{
	struct mac_vcsum vcsum;
	int match, error;
	struct hash_algo *ha;
	u_char digest[MAXCSUMSIZE];
	struct vcache *vcp;
	struct mount *mp;

	ASSERT_VOP_LOCKED(vp, "no vlock held");
	/* XXXCHKEXEC Check to see if the filesystem is read only, if it is
	 * and we are not enforcing the policy, the policy will attempt to
	 * update the filesystem which will be futile. Instead print a message
	 * to the console and grant access.
	 */
	mp = vp->v_mount;
	KASSERT(mp != NULL,
	    ("mac_chkexec NULL mount point for vnode"));
	if ((mp->mnt_flag & MNT_RDONLY) == 1 && !mac_chkexec_enforce)
		return (0);
	/* We are only interested in the execution of regular files */
	if (vp->v_type != VREG) {
		CTR0(KTR_MAC, "mac_chkexec_check: File is not VREG, skipping");
		return (0);
	}
	/*
	 * Retrieve the algorithm specified in the sysctl OID. By default
	 * we leave this as SHA1. If the algorithm is invalid, deny access
	 * since we have no way to verify the file's integrity.
	 */
	ha = mac_chkexec_get_algo();
	if (ha == NULL) {
		CTR0(KTR_MAC, "mac_chkexec_check: invalid checksum algorithm");
		return (EPERM);
	}
	/*
	 * If retrieving of the checksum stored in the file's extended
	 * attribute fails, we have no way of verifying this files integrity.
	 * Thus we will deny access to this file, erroring on the side of security.
	 */
	error = mac_chkexec_get_vcsum(vp, &vcsum);
	if (error != 0 && error != ENOATTR)
		return (error);
	/*
	 * If no checksum is present in the file, and we are ignoring
	 * un-tagged vnodes, grant execution access. Otherwise if the policy
	 * is being enforced, deny access.
	 *
	 * If the system is in "learning" mode, that is, if we are not
	 * enforcing the policy but it's enabled, then set the current
	 * file's checksum.
	 */
	if (error == ENOATTR) {
		if (mac_chkexec_ignore_untagged)
			return (0);
		if (mac_chkexec_enforce) {
			CTR0(KTR_MAC,
			    "mac_chkexec: un-registered vnode while policy enforced");
			return (EPERM);
		}
		error = ha->crypto_hash(vp, cred, digest);
		if (error)
			return (error);
		bzero(&vcsum, sizeof(vcsum));
		memcpy(vcsum.vs_sum, digest, ha->hashsize);
		vcsum.vs_flags = ha->hashmask;
		error = mac_chkexec_set_vcsum(vp, &vcsum);
		return (error);
	}
	/*
	 * To improve performance, see if we have already cached the
	 * checksum for this inode. If not, then compute the checksum
	 * and create the cache entry.
	 */
	vcp = mac_chkexec_cache_find(vp);
	if (vcp == NULL) {
		error = ha->crypto_hash(vp, cred, digest);
		if (error)
			return (error);
		mac_chkexec_cache_vcsum(vp, digest);
	} else
		memcpy(digest, vcp->digest, MAXCSUMSIZE);
	match = (memcmp(digest, vcsum.vs_sum,
	    ha->hashsize) == 0);
	if (!match && !mac_chkexec_enforce) {
		bzero(&vcsum, sizeof(vcsum));
		memcpy(vcsum.vs_sum, digest, ha->hashsize);
		vcsum.vs_flags = ha->hashmask;
		error = mac_chkexec_set_vcsum(vp, &vcsum);
		return (error);
	}
	/* If the binary itself checks out, then we should check for any
	 * dependencies it may have.
	 */
	if (match) {
		error = mac_chkexec_check_depends(vp, cred);
		if (error && mac_chkexec_enforce)
			return (error);
	}
	if (!match)
		CTR0(KTR_MAC, "mac_chkexec: checksum mismatch, denying");
	return (!match ? EPERM : 0);
}

static int
mac_chkexec_check_vnode_exec(struct ucred *cred, struct vnode *vp,
    struct label *label, struct image_params *imgp,
    struct label *execlabel)
{
	int error;

	if (!mac_chkexec_enable)
		return (0);
	ASSERT_VOP_LOCKED(vp, "no vlock held");
	error = mac_chkexec_check(vp, cred);
	return (error);
}

static int
mac_chkexec_check_vnode_mmap(struct ucred *cred, struct vnode *vp,
    struct label *label, int prot, int flags)
{
	int error;

	if (!mac_chkexec_enable)
		return (0);
	/* XXX we make the assumption that the run-time linker in userspace
	 * will be setting the appropriate permissions of this mapping. Just
	 */
	if ((prot & PROT_EXEC) == 0)
		return (0);
	ASSERT_VOP_LOCKED(vp, "no vlock held");
	error = mac_chkexec_check(vp, cred);
	return (error);
}

static int
mac_chkexec_check_kld_load(struct ucred *cred, struct vnode *vp,
    struct label *vlabel)
{
	int error;

	if (!mac_chkexec_enable)
		return (0);
	ASSERT_VOP_LOCKED(vp, "no vlock held");
	error = mac_chkexec_check(vp, cred);
	return (error);
}

/*
 * Hook certain operations from userspace which can result in in objects
 * being modified. Although we allow the modifications to these objects
 * we need to ensure that we have invalidated any cache entries associated
 * with this inode.
 */
static int
mac_chkexec_check_vnode_open(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, int acc_mode)
{

	if (!mac_chkexec_enable)
		return (0);
	if ((acc_mode & (VWRITE | VAPPEND | VADMIN)) == 0)
		return (0);
	ASSERT_VOP_LOCKED(vp, "no vlock held");
	mac_chkexec_cache_invalidate(vp);
	return (0);
}

static int
mac_chkexec_check_vnode_delete(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	struct mac_vcsum vsum;
	int error;

	if (!mac_chkexec_enable)
		return (0);
	ASSERT_VOP_LOCKED(vp, "no vlock held");
	error = mac_chkexec_get_vcsum(vp, &vsum);
	if (error)
		return (0);
	mac_chkexec_cache_invalidate(vp);
	return (0);
}

/*
 * If the subject is asking if they have execute permissions on a certain
 * object, compute the checksum of the object and check the integrity.
 * If the checksums do not match, deny access.
 */
static int
mac_chkexec_check_vnode_access(struct ucred *cred, struct vnode *vp,
    struct label *label, int acc_mode)
{
	int error;

	if (!mac_chkexec_enable)
		return (0);
	if ((acc_mode & VEXEC) == 0)
		return (0);
	ASSERT_VOP_LOCKED(vp, "no vlock held");
	error = mac_chkexec_check(vp, cred);
	return (error);
}

/*
 * Hook calls to setextattr and deleteextattr from userspace. If the policy
 * is loaded and the subject is attempting to change the namespace associated
 * with storing the checksums, deny access.
 */
static int
mac_chkexec_check_vnode_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, int attrnamespace, const char *name,
    struct uio *uio)
{

	if (!mac_chkexec_enable)
		return (0);
	if (attrnamespace != MAC_CHKEXEC_ATTRN)
		return (0);
	if (mac_chkexec_enforce) {
		CTR0(KTR_MAC, "mac_chkexec: can not setextattr on namespace while "
		    "policy is loaded");
		return (EPERM);
	}
	return (0);
}

static int
mac_chkexec_check_vnode_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *label, int attrnamespace, const char *name)
{

	if (!mac_chkexec_enable)
		return (0);
	if (attrnamespace != MAC_CHKEXEC_ATTRN)
		return (0);
	if (mac_chkexec_enforce) {
		CTR0(KTR_MAC, "mac_chkexec: can not delextattr on namespace "
		    "while policy is loaded");
		return (EPERM);
	}
	return (0);
}

static int
mac_chkexec_check_vnode_write(struct ucred *cred, struct ucred *fcred,
    struct vnode *vp, struct label *label)
{

	if (!mac_chkexec_enable)
		return (0);
	ASSERT_VOP_LOCKED(vp, "no vlock held");
	mac_chkexec_cache_invalidate(vp);
	return (0);
}

static int
mac_chkexec_syscall(struct thread *td, int call, void *arg)
{
	u_char digest[MAXCSUMSIZE];
	struct nameidata nd;
	int vfslocked, error;
	struct hash_algo *ha;
	struct mac_vcsum vcsum; 

	/*
	 * If the policy is not enabled, do nothing.
	 */
	if (!mac_chkexec_enable)
		return (0);
	/*
	 * If the policy is being enforced, deny access.
	 */
	if (mac_chkexec_enforce)
		return (EPERM);
	/*
	 * Only superuser may modify the extended attribute namespace associated
	 * with this files checksum.
	 */
	error = cap_check(td, CAP_SYS_ADMIN);
	if (error)
		return (error);
	ha = mac_chkexec_get_algo();
	if (ha == NULL) { 
		CTR0(KTR_MAC, "mac_chkexec_check: invalid checksum algorithm");
		return (EPERM);
	}
	NDINIT(&nd, LOOKUP, MPSAFE | LOCKLEAF | FOLLOW, UIO_USERSPACE, arg, td);
	if ((error = namei(&nd)) != 0) {
		return (error);
	}
	vfslocked = NDHASGIANT(&nd);
	error = ha->crypto_hash(nd.ni_vp, td->td_ucred, digest);
	if (error) {
		NDFREE(&nd, NDF_ONLY_PNBUF); 
		vput(nd.ni_vp);
		VFS_UNLOCK_GIANT(vfslocked);
		return (error);
	}
	bzero(&vcsum, sizeof(vcsum));
	memcpy(vcsum.vs_sum, digest, ha->hashsize);
	vcsum.vs_flags = ha->hashmask;
	error = mac_chkexec_set_vcsum(nd.ni_vp, &vcsum);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vput(nd.ni_vp);
	VFS_UNLOCK_GIANT(vfslocked);
	return (error);
}

static struct mac_policy_ops mac_chkexec_ops =
{
	.mpo_init = mac_chkexec_init,
	.mpo_destroy = mac_chkexec_destroy,
	.mpo_check_vnode_exec = mac_chkexec_check_vnode_exec,
	.mpo_check_vnode_mmap = mac_chkexec_check_vnode_mmap,
	.mpo_check_kld_load = mac_chkexec_check_kld_load,
	.mpo_check_vnode_open = mac_chkexec_check_vnode_open,
	.mpo_check_vnode_delete = mac_chkexec_check_vnode_delete,
	.mpo_check_vnode_access = mac_chkexec_check_vnode_access,
	.mpo_check_vnode_deleteextattr = mac_chkexec_check_vnode_deleteextattr,
	.mpo_check_vnode_setextattr = mac_chkexec_check_vnode_setextattr,
	.mpo_check_vnode_write = mac_chkexec_check_vnode_write,
	.mpo_syscall = mac_chkexec_syscall,
};

MAC_POLICY_SET(&mac_chkexec_ops, mac_chkexec, "TrustedBSD MAC/trusted exec",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
