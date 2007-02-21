#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <selinux/selinux.h>
#include <selinux/get_context_list.h>

void usage(char *name, char *detail, int rc)
{
	fprintf(stderr, "usage:  %s [-l level] user fromcon\n", name);
	if (detail)
		fprintf(stderr, "%s:  %s\n", name, detail);
	exit(rc);
}

int main(int argc, char **argv)
{
	security_context_t usercon = NULL, cur_context = NULL;
	char *user = NULL, *level = NULL, *role=NULL, *seuser=NULL, *dlevel=NULL;
	int ret, opt;

	while ((opt = getopt(argc, argv, "l:r:")) > 0) {
		switch (opt) {
		case 'l':
			level = strdup(optarg);
			break;
		case 'r':
			role = strdup(optarg);
			break;
		default:
			usage(argv[0], "invalid option", 1);
		}
	}

	if (((argc - optind) < 1) || ((argc - optind) > 2))
		usage(argv[0], "invalid number of arguments", 2);

	/* If selinux isn't available, bail out. */
	if (!is_selinux_enabled()) {
		fprintf(stderr,
			"%s may be used only on a SELinux kernel.\n", argv[0]);
		return 1;
	}

	user = argv[optind];

	/* If a context wasn't passed, use the current context. */
	if (((argc - optind) < 2)) {
		if (getcon(&cur_context) < 0) {
			fprintf(stderr, "Couldn't get current context.\n");
			return 2;
		}
	} else
		cur_context = argv[optind + 1];

	if (getseuserbyname(user, &seuser, &dlevel)==0) {
		if (! level) level=dlevel;
		if (role != NULL && role[0]) 
			ret=get_default_context_with_rolelevel(seuser, role, level,cur_context,&usercon);
		else
			ret=get_default_context_with_level(seuser, level, cur_context,&usercon);
	}
	if (ret < 0)
		perror(argv[0]);
	else
		printf("%s: %s from %s %s %s %s -> %s\n", argv[0], user, cur_context, seuser, role, level, usercon);


	free(role);
	free(seuser);
	if (level != dlevel) free(level);
	free(dlevel);
	free(usercon);

	return 0;
}
