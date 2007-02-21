#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mac.h>
#include "selinux_internal.h"

int lgetfilecon_raw(const char *path, security_context_t * context)
{
        int   ret = -1;
        mac_t mac;
        char *string;

        if (mac_prepare(&mac, "sebsd"))
	       return ret;
        if (mac_get_link(path, mac) ||
            mac_to_text(mac, &string))
                goto out;

        *context = strdup(string + strlen("sebsd/"));
        ret = strlen(*context);
        free(string);
out:
        mac_free(mac);
        return ret;
}

hidden_def(lgetfilecon_raw)

int lgetfilecon(const char *path, security_context_t * context)
{
	int ret;
	security_context_t rcontext;

	ret = lgetfilecon_raw(path, &rcontext);

	if (ret > 0) {
		ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}

	if (ret >= 0 && *context)
		return strlen(*context) + 1;
	return ret;
}
