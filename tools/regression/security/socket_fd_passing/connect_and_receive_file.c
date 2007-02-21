/*-
 * Copyright (c) 2003 Networks Associates Technologies, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by NAI Labs, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
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
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct sockaddr_un unixaddr;
	struct iovec iov;
	struct msghdr msg;
	union {
		struct cmsghdr cmsg;
		char control[CMSG_SPACE(sizeof(int))];
	} ctl;
	socklen_t len;
	int error, s, fd;

	if (argc != 2)
		errx(1, "usage: %s socket_name", argv[0]);
	s = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (s == -1)
		err(1, "creating Unix socket");
	if (strlen(argv[1]) >= sizeof(unixaddr.sun_path))
		errx(1, "connecting socket name too long");
	unixaddr.sun_family = AF_LOCAL;
	strcpy(unixaddr.sun_path, argv[1]);
	unixaddr.sun_len = strlen(unixaddr.sun_path);
	if (connect(s, (struct sockaddr *)&unixaddr, sizeof(unixaddr)) == -1)
		err(1, "connecting Unix socket");
	bzero(&msg, sizeof(msg));
	msg.msg_control = &ctl;
	msg.msg_controllen = sizeof(ctl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = &error;
	iov.iov_len = sizeof(error);
	if (recvmsg(s, &msg, 0) == -1)
		err(1, "recvmsg(SCM_RIGHTS)");
	fd = *((int *)CMSG_DATA(&ctl.cmsg));
	printf("received fd as %d\n", fd);
	printf("lseek(%d, 0, SEEK_CUR) = %lld\n", fd, lseek(fd, 0, SEEK_CUR));
	exit(0);
}

