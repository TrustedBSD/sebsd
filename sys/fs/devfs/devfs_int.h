/*-
 * Copyright (c) 2005 Poul-Henning Kamp.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/fs/devfs/devfs_int.h,v 1.2 2005/09/19 19:56:48 phk Exp $
 */

/*
 * This file documents a private interface and it SHALL only be used
 * by kern/kern_conf.c and fs/devfs/...
 */

#ifndef _FS_DEVFS_DEVFS_INT_H_
#define	_FS_DEVFS_DEVFS_INT_H_

#include <sys/queue.h>

#ifdef _KERNEL

struct devfs_dirent;

struct cdev_priv {
	struct cdev		cdp_c;
	TAILQ_ENTRY(cdev_priv)	cdp_list;

	u_int			cdp_inode;

	u_int			cdp_flags;
#define CDP_ACTIVE		(1 << 0)

	u_int			cdp_inuse;
	u_int			cdp_maxdirent;
	struct devfs_dirent	**cdp_dirents;
	struct devfs_dirent	*cdp_dirent0;
};

struct cdev *devfs_alloc(void);
void devfs_free(struct cdev *);
void devfs_create(struct cdev *dev);
void devfs_destroy(struct cdev *dev);

extern struct unrhdr *devfs_inos;
extern struct mtx devmtx;

#endif /* _KERNEL */

#endif /* !_FS_DEVFS_DEVFS_INT_H_ */
