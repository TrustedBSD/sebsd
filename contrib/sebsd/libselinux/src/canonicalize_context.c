#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"

int security_canonicalize_context_raw(security_context_t con,
				      security_context_t * canoncon)
{
        char buf[512];
        size_t buf_len;
        ssize_t con_len;
	int ret = -1;

	buf_len = sizeof(buf);
	con_len = strlen(con) + 1;
        ret = sysctlbyname("security.mac.sebsd.canon_context", buf,
            &buf_len, con, con_len);
	if (ret != 0 && errno == ENOENT) {
		/* Fall back to the original context for kernels
		   that do not support the extended interface. */
		strlcpy(buf, con, sizeof(buf));
		ret = 0;
	}
	/* Our behavior on error is different from selinux but
	   better matches how the function is actually used. */
	if (ret == 0) {
		if ((*canoncon = strdup(buf)) == NULL)
			ret = -1;
	}
	return ret;
}

hidden_def(security_canonicalize_context_raw)

int security_canonicalize_context(security_context_t con,
				  security_context_t * canoncon)
{
	int ret;
	security_context_t rcon = con;
	security_context_t rcanoncon;

	if (selinux_trans_to_raw_context(con, &rcon))
		return -1;

	ret = security_canonicalize_context_raw(rcon, &rcanoncon);

	freecon(rcon);
	if (!ret) {
		ret = selinux_raw_to_trans_context(rcanoncon, canoncon);
		freecon(rcanoncon);
	}

	return ret;
}

hidden_def(security_canonicalize_context)
