#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"

int security_check_context_raw(security_context_t con)
{
        char buf[512];
        size_t buf_len;
        ssize_t con_len;
	int ret;

	/* Just check validity, don't care about returned buffer. */
	buf_len = sizeof(buf);
	con_len = strlen(con) + 1;
        ret = sysctlbyname("security.mac.sebsd.canon_context", buf,
            &buf_len, con, con_len);
	return (ret ? -1 : 0);
}

hidden_def(security_check_context_raw)

int security_check_context(security_context_t con)
{
	int ret;
	security_context_t rcon = con;

	if (selinux_trans_to_raw_context(con, &rcon))
		return -1;

	ret = security_check_context_raw(rcon);

	freecon(rcon);

	return ret;
}

hidden_def(security_check_context)
