/*
 * Copyright (c) 2002 Poul-Henning Kamp
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Poul-Henning Kamp
 * and NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sbin/fsck_ffs/ea.c,v 1.2 2003/05/03 18:41:57 obrien Exp $");

#include <sys/param.h>
#include <sys/time.h>
#include <sys/stdint.h>

#include <ufs/ufs/dinode.h>
#include <ufs/ufs/dir.h>
#include <ufs/ffs/fs.h>

#include <err.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "fsck.h"

static int chkextattr(u_char *, int32_t);

/*
 * Scan each entry in an ea block and do basic sanity checks as per
 * those in src/sys/ufs/ffs/ffs_vnops.c:ffs_findextattr().
 */
int
eascan(struct inodesc *idesc, struct ufs2_dinode *dp)
{
	struct bufarea *bp;
	u_char *cp;
	long blksiz;
#if 0
	char tmpf[sizeof("/tmp/fsck_ffs-extent.XXXXXX")];
	int fd;
#else
	union dinode *fixdp;
#endif

	if (dp->di_extsize == 0)
		return 0;
	if (dp->di_extsize <= sblock.fs_fsize)
		blksiz = sblock.fs_fsize;
	else
		blksiz = dp->di_extsize;
	bp = getdatablk(dp->di_extb[0], blksiz);
	cp = (u_char *)bp->b_un.b_buf;
	if (chkextattr(cp, dp->di_extsize)) {
		pfatal("CORRUPT EXTENDED ATTRIBUTES I=%lu",
		    (u_long)idesc->id_number);
#if 0
		if (reply("DUMP EXTENT") == 1) {
			strcpy(tmpf, "/tmp/fsck_ffs-extent.XXXXXX");
			fd = mkstemp(tmpf);
			if (fd == -1) {
				pwarn("temp file for dump: %s\n",
				    strerror(errno));
			} else {
				pwarn("dump file at %s\n", tmpf);
				(void)write(fd, cp, dp->di_extsize);
				(void)close(fd);
			}
		}
#else
		if (reply("CLEAR") == 1) {
			fixdp = ginode(idesc->id_number);
			fixdp->dp2.di_extsize = 0;
			bzero(&fixdp->dp2.di_extb, sizeof(fixdp->dp2.di_extb));
			inodirty();
		}
#endif
	}
	bp->b_flags &= ~B_INUSE;
	return (0);
}

static int
chkextattr(u_char *ptr, int32_t length)
{
	u_char *p, *pe, *pn;
	int nlen;
	uint32_t ul, eapad2;

	pe = ptr + length;

	for (p = ptr; p < pe; p = pn) {
		bcopy(p, &ul, sizeof(ul));
		pn = p + ul;
		/* make sure this entry is complete */
		if (pn > pe)
			return (EIO);
		/* don't loop forever on a corrupt entry */
		if (pn <= p)
			return (EIO);
		p += sizeof(uint32_t);
		p++;
		eapad2 = *p++;
		/* padding is at most 7 bytes */
		if (eapad2 >= 8)
			return (EIO);
		nlen = *p;
		p++;
		/* compare only up to the end of this attribute */
		if (p + nlen > pn)
			return (EIO);
	}
	return (0);
}
