/*
 * bthidd.c
 *
 * Copyright (c) 2004 Maksim Yevmenkin <m_evmenkin@yahoo.com>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 * $FreeBSD: src/usr.sbin/bluetooth/bthidd/bthidd.c,v 1.4 2006/03/14 19:29:40 emax Exp $
 */

#include <sys/time.h>
#include <sys/queue.h>
#include <assert.h>
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <usbhid.h>
#include "bthidd.h"
#include "bthid_config.h"

static int	write_pid_file	(char const *file);
static int	remove_pid_file	(char const *file);
static int	elapsed		(int tval);
static void	sighandler	(int s);
static void	sighup		(int s);
static void	usage		(void);

/*
 * bthidd
 */

static int	done = 0;	/* are we done? */
static int	reload = 0;	/* reload config file */

int
main(int argc, char *argv[])
{
	struct bthid_server	 srv;
	struct sigaction	 sa;
	char const		*pid_file = BTHIDD_PIDFILE, *ep = NULL;
	int			 opt, detach, tval;

	memset(&srv, 0, sizeof(srv));
	memcpy(&srv.bdaddr, NG_HCI_BDADDR_ANY, sizeof(srv.bdaddr));
	srv.windex = -1;
	detach = 1;
	tval = 10; /* sec */

	while ((opt = getopt(argc, argv, "a:c:dH:hp:s:t:")) != -1) {
		switch (opt) {
		case 'a': /* BDADDR */
			if (!bt_aton(optarg, &srv.bdaddr)) {
				struct hostent  *he = NULL;

				if ((he = bt_gethostbyname(optarg)) == NULL)
					errx(1, "%s: %s", optarg, hstrerror(h_errno));

				memcpy(&srv.bdaddr, he->h_addr, sizeof(srv.bdaddr));
			}
			break;
			
		case 'c': /* config file */
			config_file = optarg;
			break;

		case 'd': /* do not detach */
			detach = 0;
			break;

		case 'H': /* hids file */
			hids_file = optarg;
			break;

		case 'p': /* pid file */
			pid_file = optarg;
			break;

		case 's': /* switch script */
			srv.script = optarg;
			break;

		case 't': /* rescan interval */
			tval = strtol(optarg, (char **) &ep, 10);
			if (*ep != '\0' || tval <= 0)
				usage();
			break;

		case 'u': /* wired keyboard index */
			srv.windex = strtol(optarg, (char **) &ep, 10);
			if (*ep != '\0' || srv.windex < 0)
				usage();
			break;

		case 'h':
		default:
			usage();
			/* NOT REACHED */
		}
	}

	openlog(BTHIDD_IDENT, LOG_PID|LOG_PERROR|LOG_NDELAY, LOG_USER);

	/* Become daemon if required */
	if (detach && daemon(0, 0) < 0) {
		syslog(LOG_CRIT, "Could not become daemon. %s (%d)",
			strerror(errno), errno);
		exit(1);
	}

	/* Install signal handler */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sighandler;

	if (sigaction(SIGTERM, &sa, NULL) < 0 ||
	    sigaction(SIGINT, &sa, NULL) < 0) {
		syslog(LOG_CRIT, "Could not install signal handlers. %s (%d)",
			strerror(errno), errno);
		exit(1);
	}

	sa.sa_handler = sighup;
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		syslog(LOG_CRIT, "Could not install signal handlers. %s (%d)",
			strerror(errno), errno);
		exit(1);
	}

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) < 0) {
		syslog(LOG_CRIT, "Could not install signal handlers. %s (%d)",
			strerror(errno), errno);
		exit(1);
	}

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		syslog(LOG_CRIT, "Could not install signal handlers. %s (%d)",
			strerror(errno), errno);
		exit(1);
	}

	if (read_config_file() < 0 || read_hids_file() < 0 ||
	    server_init(&srv) < 0 || write_pid_file(pid_file) < 0)
		exit(1);

	for (done = 0; !done; ) {
		if (elapsed(tval))
			client_rescan(&srv);

		if (server_do(&srv) < 0)
			break;

		if (reload) {
			if (write_hids_file() < 0 ||
			    read_config_file() < 0 ||
			    read_hids_file() < 0)
				break;

			reload = 0;
		}
	}

	server_shutdown(&srv);
	remove_pid_file(pid_file);
	clean_config();
	closelog();

	return (0);
}

/*
 * Write pid file
 */

static int
write_pid_file(char const *file)
{
	FILE	*pid = NULL;

	assert(file != NULL);

	if ((pid = fopen(file, "w")) == NULL) {
		syslog(LOG_ERR, "Could not open file %s. %s (%d)",
			file, strerror(errno), errno);
		return (-1);
	}

	fprintf(pid, "%d", getpid());
	fclose(pid);

	return (0);
}

/*
 * Remote pid file
 */

static int
remove_pid_file(char const *file)
{
	assert(file != NULL);

	if (unlink(file) < 0) {
		syslog(LOG_ERR, "Could not unlink file %s. %s (%d)",
			file, strerror(errno), errno);
		return (-1);
	}

	return (0);
}

/*
 * Returns true if desired time interval has elapsed
 */

static int
elapsed(int tval)
{
	static struct timeval	last = { 0, };
	struct timeval		now;

	gettimeofday(&now, NULL);

	if (now.tv_sec - last.tv_sec >= tval) {
		last = now;
		return (1);
	}

	return (0);
}

/*
 * Signal handlers
 */

static void
sighandler(int s)
{
	syslog(LOG_NOTICE, "Got signal %d, total number of signals %d",
		s, ++ done);
}

static void
sighup(int s)
{
	syslog(LOG_NOTICE, "Got SIGHUP: reload config");
	reload = 1;
}

/*
 * Display usage and exit
 */

static void
usage(void)
{
	fprintf(stderr,
"Usage: %s [options]\n" \
"Where options are:\n" \
"	-a address	specify address to listen on (default ANY)\n" \
"	-c file		specify config file name\n" \
"	-d		run in foreground\n" \
"	-H file		specify known HIDs file name\n" \
"	-h		display this message\n" \
"	-p file		specify PID file name\n" \
"	-s script	specify keyboard switching script\n" \
"	-t tval		specify client rescan interval (sec)\n" \
"	-u unit		specify wired keyboard unit\n" \
"", BTHIDD_IDENT);
	exit(255);
}

