
/* Author : Stephen Smalley (NAI Labs), <ssmalley@nai.com> */

/* FLASK */

/*
 * Initialize the security server by reading the policy
 * database and initializing the SID table.
 */


#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/linker.h>

#include <security/sebsd/linux-compat.h>
#include <security/sebsd/sebsd.h>
#include <security/sebsd/ss/global.h>
#include <security/sebsd/ss/policydb.h>
#include <security/sebsd/ss/services.h>
#include <security/sebsd/ss/security.h>

const char *sebsd_policy_path;

int security_init(void)
{
	int rc;
	caddr_t  lh, tmp;
	void    *policy_data;
	size_t   policy_len;

	printf("security:  starting up (compiled " __DATE__ ")\n");

	lh = preload_search_by_type ("sebsd_policy");
	if (lh == NULL)
		goto loaderr;

	tmp = preload_search_info (lh, MODINFO_ADDR);
	if (tmp == NULL)
		goto loaderr;
	policy_data = *(void **) tmp;
	tmp = preload_search_info (lh, MODINFO_SIZE);
	if (tmp == NULL)
		goto loaderr;
	policy_len = *(size_t *) tmp;
	sebsd_policy_path = lh + sizeof(u_int32_t) * 2;

	printf("security:  reading policy configuration\n");

	rc = security_load_policy(policy_data, policy_len);
	if (rc) {
		printf("security:  error while reading policy, cannot initialize.\n");
		return EINVAL;
	}

	return 0;

loaderr:
	printf("security:  policy not supplied by bootloader\n");
	return EINVAL;
}

/* FLASK */
