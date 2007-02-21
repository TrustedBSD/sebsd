#include "selinux_internal.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mac.h>
#include "policy.h"

int getcon_raw(security_context_t * context)
{
        mac_t label;
        char *string;
        int error;
	int ret = 0;

        error = mac_prepare(&label, "sebsd");
	if (error)
		return -1;
        error = mac_get_proc(label);
        if (error) {
		ret = -1;
		goto out;
	}
        error = mac_to_text(label, &string);
	if (error || string == NULL) {
		ret = -1;
		goto out;
	}
        *context = strdup(string + sizeof("sebsd/") - 1);
        free(string);
out:
	mac_free(label);
	return ret;
}

hidden_def(getcon_raw)

int getcon(security_context_t * context)
{
	int ret;
	security_context_t rcontext;

	ret = getcon_raw(&rcontext);

	if (!ret) {
		ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}

	return ret;
}

hidden_def(getcon)
