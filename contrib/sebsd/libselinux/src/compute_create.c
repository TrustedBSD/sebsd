#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"

int security_compute_create_raw(security_context_t scon,
				security_context_t tcon,
				security_class_t tclass,
				security_context_t * newcon)
{
        char *arguments = NULL, buf[512];
        size_t buf_len;
        ssize_t arguments_len;
	int ret = -1;

        arguments_len = asprintf(&arguments, "%s%c%s%c%s", scon, '\0',
            tcon, '\0', "X");
        if (arguments_len == -1)
                goto out;
        memcpy(&arguments[arguments_len - 1], &tclass, sizeof(tclass));
        buf_len = sizeof(buf);
        if (sysctlbyname("security.mac.sebsd.compute_create", buf,
            &buf_len, arguments, arguments_len) == -1)
                goto out;
	*newcon = strdup(buf);
	if ((*newcon) != NULL)
		ret = 0;
      out:
        free(arguments);
        return (ret);
}

hidden_def(security_compute_create_raw)

int security_compute_create(security_context_t scon,
			    security_context_t tcon,
			    security_class_t tclass,
			    security_context_t * newcon)
{
	int ret;
	security_context_t rscon = scon;
	security_context_t rtcon = tcon;
	security_context_t rnewcon;

	if (selinux_trans_to_raw_context(scon, &rscon))
		return -1;
	if (selinux_trans_to_raw_context(tcon, &rtcon)) {
		freecon(rscon);
		return -1;
	}

	ret = security_compute_create_raw(rscon, rtcon, tclass, &rnewcon);

	freecon(rscon);
	freecon(rtcon);
	if (!ret) {
		ret = selinux_raw_to_trans_context(rnewcon, newcon);
		freecon(rnewcon);
	}

	return ret;
}

hidden_def(security_compute_create)
