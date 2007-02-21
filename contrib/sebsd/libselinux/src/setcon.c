/*
 * Author: Trusted Computer Solutions, Inc. <chanson@trustedcs.com>
 */

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mac.h>
#include "selinux_internal.h"

int setcon_raw(security_context_t context)
{
	mac_t label;
	int error;
	
	error = mac_from_text(&label, context);
	if (error)
		return -1;
	error = mac_set_proc(label);
	mac_free(label);
	if (error)
		return -1;
	return 0;
}

hidden_def(setcon_raw)

int setcon(char *context)
{
        int ret;
        security_context_t rcontext = context;

        if (selinux_trans_to_raw_context(context, &rcontext))
                return -1;

        ret = setcon_raw(rcontext);

	freecon(rcontext);

        return ret;
}
