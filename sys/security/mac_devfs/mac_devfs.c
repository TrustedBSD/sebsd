/*-
 * Copyright (c) 2005 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
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
 *
 * $FreeBSD$
 */

/*
 * Developed by the TrustedBSD Project.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/acl.h>
#include <sys/conf.h>
#include <sys/extattr.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/pipe.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#include <fs/devfs/devfs.h>

#include <net/bpfdesc.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/ip_var.h>

#include <vm/vm.h>

#include <sys/mac_policy.h>

static int
interesting(const char *str1, const char *str2)
{

	if (str1 == NULL || str2 == NULL)
		return (0);
	if (strcmp(str1, str2) == 0)
		return (0);
	return (1);
}

static void
mac_devfs_associate_vnode_devfs(struct mount *mp, struct label *fslabel,
    struct devfs_dirent *de, struct label *delabel, struct vnode *vp,
    struct label *vlabel)
{

}

static void
mac_devfs_create_devfs_device(struct ucred *cred, struct mount *mp,
    struct cdev *dev, struct devfs_dirent *devfs_dirent, struct label *label,
    const char *fullpath)   
{  

	if (!interesting(dev->si_name, fullpath))
		return;

	printf("mac_devfs_create_devfs_device(uid %d mp %s cdev %s "
	    "fullpath %s)\n", cred != NULL ? cred->cr_uid : -1,
	    mp->mnt_stat.f_mntonname, dev->si_name, fullpath);
}

static void
mac_devfs_create_devfs_directory(struct mount *mp, char *dirname,
    int dirnamelen, struct devfs_dirent *devfs_dirent, struct label *label,
    const char *fullpath)
{

	if (!interesting(dirname, fullpath))
		return;

	printf("mac_devfs_create_devfs_directory(mp %s dirname %s "
	    "fullpath %s)\n", mp->mnt_stat.f_mntonname, dirname, fullpath);
}

static void
mac_devfs_create_devfs_symlink(struct ucred *cred, struct mount *mp,
    struct devfs_dirent *dd, struct label *ddlabel, struct devfs_dirent *de,
    struct label *delabel, const char *fullpath)
{

	printf("mac_devfs_create_devfs_symlink(uid %d mp %s fullpath %s)\n",
	    cred != NULL ? cred->cr_uid : -1, mp->mnt_stat.f_mntonname,
	    fullpath);
}

static struct mac_policy_ops mac_none_ops =
{
	.mpo_associate_vnode_devfs = mac_devfs_associate_vnode_devfs,
	.mpo_create_devfs_device = mac_devfs_create_devfs_device,
	.mpo_create_devfs_directory = mac_devfs_create_devfs_directory,
	.mpo_create_devfs_symlink = mac_devfs_create_devfs_symlink,
};

MAC_POLICY_SET(&mac_none_ops, mac_none, "TrustedBSD MAC/devfs",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
