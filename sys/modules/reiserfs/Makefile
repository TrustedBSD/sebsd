# $FreeBSD: src/sys/modules/reiserfs/Makefile,v 1.2 2005/06/18 17:10:50 dumbbell Exp $

.PATH: ${.CURDIR}/../../gnu/fs/reiserfs
KMOD=	reiserfs
SRCS=	vnode_if.h \
	reiserfs_fs.h reiserfs_fs_i.h reiserfs_fs_sb.h reiserfs_hashes.c \
	reiserfs_inode.c reiserfs_item_ops.c reiserfs_mount.h \
	reiserfs_namei.c reiserfs_prints.c reiserfs_stree.c \
	reiserfs_vfsops.c reiserfs_vnops.c

.include <bsd.kmod.mk>
