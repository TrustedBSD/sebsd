#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mac.h>
#include "selinux_internal.h"
#include "policy.h"

int getpeercon_raw(int fd, security_context_t * context)
{
	int   ret = -1;
	mac_t mac;
	char *string;

	if (mac_prepare(&mac, "sebsd"))
		return ret;
	
	if (mac_get_peer(fd, mac) ||
	    mac_to_text(mac, &string))
		goto out;

	*context = strdup(string + strlen("sebsd/"));
	if (*context != NULL)
		ret = 0;
	free(string);
out:
	mac_free(mac);
	return ret;
}

hidden_def(getpeercon_raw)

int getpeercon(int fd, security_context_t * context)
{
	int ret;
	security_context_t rcontext;

	ret = getpeercon_raw(fd, &rcontext);

	if (!ret) {
		ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}

	return ret;
}
