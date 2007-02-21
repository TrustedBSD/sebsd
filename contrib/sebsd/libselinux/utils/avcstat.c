/*
 * avcstat - Display SELinux avc statistics.
 *
 * Copyright (C) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#define HEADERS		"lookups hits misses allocations reclaims frees"

struct avc_cache_stats {
	unsigned long long lookups;
	unsigned long long hits;
	unsigned long long misses;
	unsigned long long allocations;
	unsigned long long reclaims;
	unsigned long long frees;
};

static int interval;
static int rows;
static char *progname;
static void die(const char *msg, ...)
{
	va_list args;

	fputs("ERROR: ", stderr);

	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);

	if (errno)
		fprintf(stderr, ": %s", strerror(errno));

	fputc('\n', stderr);
	exit(1);
}

static void usage(void)
{
	printf("\nUsage: %s [-c] [interval]\n\n", progname);
	printf
	    ("Display SELinux AVC statistics.  If the interval parameter is specified, the\n");
	printf
	    ("program will loop, displaying updated statistics every \'interval\' seconds.\n");
	printf
	    ("Relative values are displayed by default. Use the -c option to specify the\n");
	printf
	    ("display of cumulative values.\n\n");
}

static void set_window_rows(void)
{
	int ret;
	struct winsize ws;

	ret = ioctl(fileno(stdout), TIOCGWINSZ, &ws);
	if (ret < 0 || ws.ws_row < 3)
		ws.ws_row = 24;
	rows = ws.ws_row;
}

static void sighandler(int num)
{
	if (num == SIGWINCH)
		set_window_rows();
}

int main(int argc, char **argv)
{
	struct avc_cache_stats tot, rel, last;
	int i, ret, cumulative = 0;
	struct sigaction sa;

	progname = basename(argv[0]);

	memset(&last, 0, sizeof(last));

	while ((i = getopt(argc, argv, "cf:h?-")) != -1) {
		switch (i) {
		case 'c':
			cumulative = 1;
			break;
		case 'h':
		case '-':
			usage();
			exit(0);
		default:
			usage();
			die("unrecognized parameter", i);
		}
	}

	if (optind < argc) {
		char *arg = argv[optind];
		unsigned int n = strtoul(arg, NULL, 10);

		if (errno == ERANGE) {
			usage();
			die("invalid interval \'%s\'", arg);
		}
		if (n == 0) {
			usage();
			exit(0);
		}
		interval = n;
	}

	sa.sa_handler = sighandler;
	sa.sa_flags = SA_RESTART;

	i = sigaction(SIGWINCH, &sa, NULL);
	if (i < 0)
		die("sigaction");

	set_window_rows();

	for (i = 0;; i++) {
		struct avc_cache_stats tmp;
		size_t tsize = sizeof(tmp);

		ret = sysctlbyname("security.mac.sebsd.avcstats", &tmp,
		    &tsize, NULL, 0);
		if (ret != 0)
			die("unable to look up security.mac.sebsd.avcstats");

		if (!i || !(i % (rows - 2)))
			printf("%10s %10s %10s %10s %10s %10s\n", "lookups",
			       "hits", "misses", "allocs", "reclaims", "frees");

		memset(&tot, 0, sizeof(tot));

		tot.lookups += tmp.lookups;
		tot.hits += tmp.hits;
		tot.misses += tmp.misses;
		tot.allocations += tmp.allocations;
		tot.reclaims += tmp.reclaims;
		tot.frees += tmp.frees;

		if (cumulative || (!cumulative && !i))
			printf("%10Lu %10Lu %10Lu %10Lu %10Lu %10Lu\n",
			       tot.lookups, tot.hits, tot.misses,
			       tot.allocations, tot.reclaims, tot.frees);
		else {
			rel.lookups = tot.lookups - last.lookups;
			rel.hits = tot.hits - last.hits;
			rel.misses = tot.misses - last.misses;
			rel.allocations = tot.allocations - last.allocations;
			rel.reclaims = tot.reclaims - last.reclaims;
			rel.frees = tot.frees - last.frees;
			printf("%10Lu %10Lu %10Lu %10Lu %10Lu %10Lu\n",
			       rel.lookups, rel.hits, rel.misses,
			       rel.allocations, rel.reclaims, rel.frees);
		}

		if (!interval)
			break;

		memcpy(&last, &tot, sizeof(last));
		sleep(interval);
	}

	return 0;
}
