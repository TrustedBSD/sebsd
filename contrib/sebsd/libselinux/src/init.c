#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include "dso.h"
#include "selinux_internal.h"
#include "setrans_internal.h"

char *selinux_mnt = NULL;
int selinux_page_size = 0;

static void init_lib(void) __attribute__ ((constructor));
static void init_lib(void)
{
	selinux_page_size = sysconf(_SC_PAGE_SIZE);
	init_context_translations();
}

static void fini_lib(void) __attribute__ ((destructor));
static void fini_lib(void)
{
	fini_context_translations();
}
