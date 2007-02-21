#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mac.h>
#include "selinux_internal.h"

int getexeccon_raw(security_context_t * context)
{
	/* XXX - SEBSD doesn't support a separate exec context */
        return getcon_raw(context);
}

hidden_def(getexeccon_raw)

int getexeccon(security_context_t * context)
{
	/* XXX - SEBSD doesn't support a separate exec context */
        return getcon(context);
}
