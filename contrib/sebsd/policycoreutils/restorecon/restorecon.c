/* 
 * restorecon
 *
 * AUTHOR:  Dan Walsh <dwalsh@redhat.com>
 *
 * PURPOSE:
 * This program takes a list of files and sets their security context
 * to match the specification returned by matchpathcon.
 *
 * USAGE:
 * restorecon [-Rnv] pathname...
 * 
 * -e   Specify directory to exclude
 * -i   Ignore error if file does not exist
 * -n	Do not change any file labels.
 * -v	Show changes in file labels.  
 * -o	filename save list of files with incorrect context
 * -F	Force reset of context to match file_context for customizable files
 *
 * pathname...	The file(s) to label 
 *
 * EXAMPLE USAGE:
 * restorecon /dev/tty*
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <selinux/selinux.h>
#include <selinux/secompat.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <fts.h>

static int change = 1;
static int verbose = 0;
static int progress = 0;
static FILE *outfile = NULL;
static char *progname;
static int errors = 0;
static int recurse = 0;
static int file_exist = 1;
static int force = 0;
static unsigned long long count = 0;

#define MAX_EXCLUDES 100
static int excludeCtr = 0;
struct edir {
	char *directory;
	size_t size;
};
static struct edir excludeArray[MAX_EXCLUDES];
static int add_exclude(const char *directory)
{
	struct stat sb;
	size_t len = 0;
	if (directory == NULL || directory[0] != '/') {
		fprintf(stderr, "Full path required for exclude: %s.\n",
			directory);
		return 1;
	}
	if (lstat(directory, &sb)) {
		fprintf(stderr, "Directory \"%s\" not found, ignoring.\n",
			directory);
		return 0;
	}
	if ((sb.st_mode & S_IFDIR) == 0) {
		fprintf(stderr,
			"\"%s\" is not a Directory: mode %o, ignoring\n",
			directory, sb.st_mode);
		return 0;
	}

	if (excludeCtr == MAX_EXCLUDES) {
		fprintf(stderr, "Maximum excludes %d exceeded.\n",
			MAX_EXCLUDES);
		return 1;
	}

	len = strlen(directory);
	while (len > 1 && directory[len - 1] == '/') {
		len--;
	}
	excludeArray[excludeCtr].directory = strndup(directory, len);

	if (excludeArray[excludeCtr].directory == NULL) {
		fprintf(stderr, "Out of memory.\n");
		return 1;
	}
	excludeArray[excludeCtr++].size = len;

	return 0;
}
static int exclude(const char *file)
{
	int i = 0;
	for (i = 0; i < excludeCtr; i++) {
		if (strncmp
		    (file, excludeArray[i].directory,
		     excludeArray[i].size) == 0) {
			if (file[excludeArray[i].size] == 0
			    || file[excludeArray[i].size] == '/') {
				return 1;
			}
		}
	}
	return 0;
}

/* Compare two contexts to see if their differences are "significant",
 * or whether the only difference is in the user. */
static int only_changed_user(const char *a, const char *b)
{
	char *rest_a, *rest_b;	/* Rest of the context after the user */
	if (force)
		return 0;
	if (!a || !b)
		return 0;
	rest_a = strchr(a, ':');
	rest_b = strchr(b, ':');
	if (!rest_a || !rest_b)
		return 0;
	return (strcmp(rest_a, rest_b) == 0);
}

void usage(const char *const name)
{
	fprintf(stderr,
		"usage:  %s [-iFnrRv] [-e excludedir ] [-o filename ] [-f filename | pathname... ]\n",
		name);
	exit(1);
}

/* filename has trailing '/' removed by fts or other calling code */
int restore(const char *filename)
{
	int retcontext = 0;
	security_context_t scontext = NULL;
	security_context_t prev_context = NULL;
	struct stat st;
	char path[PATH_MAX + 1];

	if (progress) {
		count++;
		if (count % 80000 == 0) {
			fprintf(stdout, "\n");
			fflush(stdout);
		}
		if (count % 1000 == 0) {
			fprintf(stdout, "*");
			fflush(stdout);
		}
	}

	if (excludeCtr > 0 && exclude(filename)) {
		return 0;
	}

	if (lstat(filename, &st) != 0) {
		if (!file_exist && errno == ENOENT)
			return 0;
		fprintf(stderr, "lstat(%s) failed: %s\n", filename,
			strerror(errno));
		return 1;
	}
	if (S_ISLNK(st.st_mode)) {
		if (verbose > 1)
			fprintf(stderr,
				"Warning! %s refers to a symbolic link, not following last component.\n",
				filename);
		char *p = NULL, *file_sep;
		char *tmp_path = strdupa(filename);
		size_t len = 0;

		if (!tmp_path) {
			fprintf(stderr, "strdupa on %s failed:  %s\n", filename,
				strerror(errno));
			return 1;
		}
		file_sep = strrchr(tmp_path, '/');
		if (file_sep == tmp_path) {
			file_sep++;
			p = strcpy(path, "");
		} else if (file_sep) {
			*file_sep = 0;
			file_sep++;
			p = realpath(tmp_path, path);
		} else {
			file_sep = tmp_path;
			p = realpath("./", path);
		}
		if (p)
			len = strlen(p);
		if (!p || len + strlen(file_sep) + 2 > PATH_MAX) {
			fprintf(stderr, "realpath(%s) failed %s\n", filename,
				strerror(errno));
			return 1;
		}
		p += len;
		/* ensure trailing slash of directory name */
		if (len == 0 || *(p - 1) != '/') {
			*p = '/';
			p++;
		}
		strcpy(p, file_sep);
		filename = path;
	} else {
		char *p;
		p = realpath(filename, path);
		if (!p) {
			fprintf(stderr, "realpath(%s) failed %s\n", filename,
				strerror(errno));
			return 1;
		}
		filename = p;
	}
	if (excludeCtr > 0 && exclude(filename)) {
		return 0;
	}
	if (matchpathcon(filename, st.st_mode, &scontext) < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf(stderr, "matchpathcon(%s) failed %s\n", filename,
			strerror(errno));
		return 1;
	}
	retcontext = lgetfilecon_raw(filename, &prev_context);

	if (retcontext >= 0) {
		int customizable = 0;
		if (force ||
		    (strcmp(prev_context, scontext) != 0 &&
		     !(customizable =
		       is_context_customizable(prev_context) > 0))) {
			if (only_changed_user(scontext, prev_context) == 0) {
				if (outfile)
					fprintf(outfile, "%s\n", filename);
				if (change) {
					if (lsetfilecon(filename, scontext) < 0) {
						fprintf(stderr,
							"%s set context %s->%s failed:'%s'\n",
							progname, filename,
							scontext,
							strerror(errno));
						freecon(prev_context);
						freecon(scontext);
						return 1;
					}
				} 

				if (verbose)
					printf("%s reset %s context %s->%s\n",
					       progname, filename,
					       prev_context, scontext);
			}
		}
		if (verbose > 1 && !force && customizable > 0) {
			printf("%s: %s not reset customized by admin to %s\n",
			       progname, filename, prev_context);
		}

		freecon(prev_context);
	} else {
		errors++;
		fprintf(stderr, "%s get context on %s failed: '%s'\n",
			progname, filename, strerror(errno));
	}
	freecon(scontext);
	return errors;
}

static int apply_spec(const char *file, const struct stat *sb)
{
	errors += restore(file);
	return 0;
}
void process(char *buf)
{
	if (recurse) {
		FTS *fts;
		FTSENT *ftsent;
		char *av[2] = {buf, NULL};

		fts = fts_open(av, FTS_PHYSICAL | FTS_COMFOLLOW, NULL);
		if (fts == NULL) {
			fprintf(stderr,
			    "%s:  error while labeling files under %s\n",
			    progname, buf);
			errors++;
			return;
		}
		while ((ftsent = fts_read(fts)) != NULL) {
			switch (ftsent->fts_info) {
			case FTS_D:		/* dir in pre-order */
				if (fts->fts_dev != ftsent->fts_dev)
					break;
				/* FALLTHROUGH */
			case FTS_F:		/* file */
			case FTS_SL:		/* symlink */
			case FTS_W:		/* whiteout */
			case FTS_DEFAULT:
				apply_spec(ftsent->fts_path, ftsent->fts_statp);
				break;
			case FTS_DNR:
				if (!file_exist && errno == ENOENT)
					return;
				fprintf(stderr,
				    "%s:  unable to read directory %s\n",
				    progname, ftsent->fts_path);
				break;
			case FTS_NS:
				fprintf(stderr, "%s:  unable to stat file %s\n",
				    progname, ftsent->fts_path);
				break;
			case FTS_ERR:
				fprintf(stderr, "%s:  %s:  %s\n",
				    progname, ftsent->fts_path,
				    strerror(ftsent->fts_errno));
				break;
			case FTS_DP:		/* skip post-order dir */
			case FTS_DC:		/* skip dir cycle */
			case FTS_DOT:		/* skip . and .. */
			case FTS_SLNONE:	/* skip dead symlinks */
			default:
				break;
			}
		}
	} else {
		/* Eliminate trailing / */
		size_t len = strlen(buf);
		if (len > 1 && buf[len - 1] == '/') {
			buf[len - 1] = 0;
		}
		errors = errors + restore(buf);
	}
}
int main(int argc, char **argv)
{
	int i = 0;
	char *file_name = NULL;
	int file = 0;
	int opt;
	char *buf = NULL;
	size_t buf_len;

	memset(excludeArray, 0, sizeof(excludeArray));

	progname = argv[0];
	if (is_selinux_enabled() <= 0)
		exit(0);

	set_matchpathcon_flags(MATCHPATHCON_NOTRANS);

	while ((opt = getopt(argc, argv, "ipFrRnvf:o:e:")) > 0) {
		switch (opt) {
		case 'n':
			change = 0;
			break;
		case 'i':
			file_exist = 0;
			break;
		case 'r':
		case 'R':
			recurse = 1;
			break;
		case 'F':
			force = 1;
			break;
		case 'e':
			if (add_exclude(optarg))
				exit(1);
			break;
		case 'o':
			if (strcmp(optarg, "-") == 0)
				outfile = stdout;
			else {
				outfile = fopen(optarg, "w");
				if (!outfile) {
					fprintf(stderr,
						"Error opening %s: %s\n",
						optarg, strerror(errno));
					usage(argv[0]);
				}
			}
			break;
		case 'v':
			if (progress) {
				fprintf(stderr,
					"Progress and Verbose mutually exclusive\n");
				usage(argv[0]);
			}

			verbose++;
			break;
		case 'p':
			if (verbose) {
				fprintf(stderr,
					"Progress and Verbose mutually exclusive\n");
				usage(argv[0]);
			}
			progress = 1;
			break;
		case 'f':
			file = 1;
			file_name = optarg;
			break;
		case '?':
			usage(argv[0]);
		}
	}
	if (file) {
		FILE *f = stdin;
		ssize_t len;
		if (strcmp(file_name, "-") != 0)
			f = fopen(file_name, "r");
		if (f == NULL) {
			fprintf(stderr, "Unable to open %s: %s\n", file_name,
				strerror(errno));
			usage(argv[0]);
		}
		while ((len = getline(&buf, &buf_len, f)) != -1) {
			buf[len - 1] = 0;
			process(buf);
		}
		if (strcmp(file_name, "-") != 0)
			fclose(f);
	} else {
		if (optind >= argc)
			usage(argv[0]);
		for (i = optind; i < argc; i++) {
			process(argv[i]);
		}
	}
	if (outfile)
		fclose(outfile);

	return errors;
}
