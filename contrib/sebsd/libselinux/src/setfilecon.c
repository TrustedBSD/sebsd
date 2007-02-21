#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mac.h>
#include "selinux_internal.h"

int setfilecon_raw(const char *path, security_context_t context)
{
        mac_t mac;
        char  tmp[strlen(context) + strlen("sebsd/0")];
        int   ret;

        strcpy(tmp, "sebsd/");
        strcat(tmp, context);
        if (mac_from_text(&mac, tmp))
                return -1;
        ret = mac_set_file(path, mac);
        mac_free(mac);
        return ret;
}

hidden_def(setfilecon_raw)

int setfilecon(const char *path, security_context_t context)
{
	int ret;
	security_context_t rcontext = context;

	if (selinux_trans_to_raw_context(context, &rcontext))
		return -1;

	ret = setfilecon_raw(path, rcontext);

	freecon(rcontext);

	return ret;
}
