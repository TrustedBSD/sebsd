#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mac.h>
#include "selinux_internal.h"
#include "policy.h"

int fgetfilecon_raw(int fd, security_context_t * context)
{
        int   r = -1;
        mac_t mac;
        char *string;

	if (mac_prepare(&mac, "sebsd"))
		return r;
	
        if (mac_get_fd(fd, mac) ||
            mac_to_text(mac, &string))
                goto out;

        *context = strdup(string + strlen("sebsd/"));
        r = strlen(*context);
        free(string);
out:
        mac_free(mac);
        return r;
}

hidden_def(fgetfilecon_raw)

int fgetfilecon(int fd, security_context_t * context)
{
	security_context_t rcontext;
	int ret;

	ret = fgetfilecon_raw(fd, &rcontext);

	if (ret > 0) {
		ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}

	if (ret >= 0 && *context)
		return strlen(*context) + 1;

	return ret;
}
