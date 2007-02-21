/*-
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
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/extattr.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include <security/mac_chkexec/mac_chkexec.h>

#include <sha.h>
#include <md5.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static void	print_hash(const char *);
static void	process_depends(const char *);
static void	set_hash(const char *);
static int	print_hash_from_stdin(void);

static int	 depth;
static int	 eval;

static int	 dflag;
static int	 fflag;
static int	 rflag;
static char	*mflag;
static int	 Wflag;

static void	(*handler)(const char *);

static int
calc_sha1(const char *fname, u_char *digest)
{
	SHA1_CTX	ctx;
	int	fd, len, error, count;
	struct stat sb;
	off_t b;
	char *buffer;

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		warn("open failed");
		return (fd);
	}
	if (fstat(fd, &sb) < 0) {
		warn("fstat failed");
		close(fd);
		return (-1);
	}
	len = getpagesize();
	buffer = malloc(len);
	SHA1_Init(&ctx);
	for (b = 0; b < sb.st_size; b += len) {
		if ((len + b) > sb.st_size)
			count = sb.st_size - b;
		else
			count = len;
		error = read(fd, buffer, count);
		if (error < 0) {
			close(fd);
			free(buffer);
			warn("read failed");
			return (error);
		}
		SHA1_Update(&ctx, buffer, count);
	}
	close(fd);
	SHA1_Final(digest, &ctx);
	free(buffer);
	return (0);
}

static int
calc_md5(const char *fname, u_char *digest)
{
        MD5_CTX        ctx;
        int     fd, len, error, count;
        struct stat sb;
        off_t b;
        char *buffer;  
  
        fd = open(fname, O_RDONLY);
        if (fd < 0) {
                warn("open failed");
                return (fd);
        }
        if (fstat(fd, &sb) < 0) {
                warn("fstat failed");
                close(fd);
                return (-1);
        }
        len = getpagesize();
        buffer = malloc(len);
        MD5Init(&ctx);
        for (b = 0; b < sb.st_size; b += len) {
                if ((len + b) > sb.st_size)
                        count = sb.st_size - b;
                else
                        count = len;
                error = read(fd, buffer, count);
                if (error < 0) {
                        close(fd);
                        free(buffer);
                        warn("read failed");
                        return (error);
                }
                MD5Update(&ctx, buffer, count);
        }
        close(fd);
        MD5Final(digest, &ctx);
        free(buffer);
        return (0);
}

static void
process_depends(const char *pathname)
{
	char *av, *dependlist;
	int error, j;
	ssize_t nbytes;

	nbytes = extattr_get_file(pathname, MAC_CHKEXEC_ATTRN,
	    MAC_CHKEXEC_DEP, NULL, 0);
	if (nbytes < 0 && errno == ENOATTR)
		return;
	else if (nbytes < 0) {
		warn("extattr_get_file failed");
		return;
	}
	dependlist = malloc(nbytes + 1);
	if (dependlist == NULL) {
		warn("malloc failed");
		return;
	}
	error = extattr_get_file(pathname, MAC_CHKEXEC_ATTRN,
	    MAC_CHKEXEC_DEP, dependlist, nbytes);
	dependlist[nbytes] = '\0';
	depth++;
	for (; (av = strsep(&dependlist, ":")) != NULL;) {
		if (strlen(av) == 0)
			continue;
		for (j = 0; j < depth; j++)
			fputs("    ", stdout);
		print_hash(av);
        }
	depth--;
}

static void
set_hash(const char *pathname)
{
	struct stat sb;
	int error;
	size_t slen;

	if (rflag) {
		error = extattr_delete_file(pathname, MAC_CHKEXEC_ATTRN,
		    MAC_CHKEXEC_DEP);
		if (error < 0)
			warn("extattr_delete_file failed");
		return;
	}
	if (syscall(SYS_mac_syscall, "mac_chkexec", 0, pathname) < 0) {
		eval++;
		warn("%s", pathname);
	}
	if (!mflag)
		return;
	if (stat(mflag, &sb) < 0)
		fprintf(stderr, "WARNING: %s: %s\n", mflag, strerror(errno));
	slen = strlen(mflag);
	error = extattr_set_file(pathname, MAC_CHKEXEC_ATTRN,
	    MAC_CHKEXEC_DEP, mflag, slen);
	if (error < 0) {
		eval++;
		warn("extattr_set_file failed");
	}
}

static void
print_hash(const char *pathname)
{
	struct mac_vcsum sum;
	int i, error;
	int nbytes;
	const char *algo;
	u_char digest[64];
	int (*checksum)(const char *, u_char *);

again:
	error = extattr_get_file(pathname, MAC_CHKEXEC_ATTRN,
	    MAC_CHKEXEC, (void *)&sum, sizeof(sum));
	if (error < 0 && errno == ENOATTR && fflag) {
		if (syscall(SYS_mac_syscall, "mac_chkexec", 0, pathname) < 0)
			warn("%s", pathname);
		else
			goto again;
        } else if (error < 0) {
		warn("%s", pathname);
		return;
	}
	if (sum.vs_flags == MAC_VCSUM_SHA1) {
		nbytes = SHA1_HASH_SIZE;
		algo = "sha1";
		checksum = calc_sha1;
	}
	else if (sum.vs_flags == MAC_VCSUM_MD5) {
		nbytes = MD5_HASH_SIZE;
		algo = "md5";
		checksum = calc_md5;
	} else {
		warnx("%s: invalid checksum algorithm",
		    pathname);
		return;
	}
	printf("%s: %s ", pathname, algo);
	for (i = 0; i < nbytes; i++)
		printf("%02x", sum.vs_sum[i]);
	if (Wflag) {
		(*checksum)(pathname, &digest[0]);
		if (memcmp(&digest[0], &sum.vs_sum[0], nbytes) != 0) {
			warnx("%s: checksum discrepancy", pathname);
		}
	}
	putchar('\n');
	if (dflag)
		process_depends(pathname);
}

static int
print_hash_from_stdin(void)
{
	char *p, pathname[256];

	while (fgets(pathname, (int)sizeof(pathname), stdin)) {
		if ((p = strchr(pathname, '\n')) != NULL)
			*p = '\0';
		handler(pathname);
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	int ch, error, i;
	char *program;

	if ((program = strrchr(argv[0], '/')) == NULL)
		program = argv[0];
	else
		program++;
	if (strcmp(program, "setfhash") == 0)
		handler = set_hash;
	else if (strcmp(program, "getfhash") == 0)
		handler = print_hash;
	else
		errx(1, "what program am I supposed to be?");
	while ((ch = getopt(argc, argv, "dfhm:rW")) != -1)
		switch(ch) {
		case 'd':
			dflag++;
			break;
		case 'f':
			fflag++;
			break;
		case 'm':
			mflag = optarg;
			break;
		case 'r':
			rflag++;
			break;
		case 'W':
			Wflag++;
			break;
		default:
			break;
		}
	argc -= optind;
	argv += optind;
	if (argc == 0) {
		error = print_hash_from_stdin();
		return (error ? 1 : 0);
	}
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-")) {
			error = print_hash_from_stdin();
		} else 
			handler(argv[i]);
	}
	return (eval);
}
