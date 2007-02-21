#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mac.h>
#include "selinux_internal.h"

int getpidcon_raw(pid_t pid, security_context_t * context)
{
        int   ret = -1;
        mac_t mac;
        char *string;

	if (mac_prepare(&mac, "sebsd"))
		return ret;
	
        if (mac_get_pid(pid, mac) ||
            mac_to_text(mac, &string))
                goto out;

        *context = strdup(string + strlen("sebsd/"));
        free(string);
        ret = 0;
out:
        mac_free(mac);
        return ret;
}

hidden_def(getpidcon_raw)

int getpidcon(pid_t pid, security_context_t * context)
{
	int ret;
	security_context_t rcontext;

	ret = getpidcon_raw(pid, &rcontext);
	if (!ret) {
		ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}

	return ret;
}
