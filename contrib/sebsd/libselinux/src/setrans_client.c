/* Copyright (c) 2006 Trusted Computer Solutions, Inc. */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <errno.h>
#include <stdlib.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "dso.h"
#include "selinux_internal.h"
#include "setrans_internal.h"

static int mls_enabled = -1;

// Simple cache
static security_context_t prev_t2r_trans = NULL;
static security_context_t prev_t2r_raw = NULL;
static security_context_t prev_r2t_trans = NULL;
static security_context_t prev_r2t_raw = NULL;

int cache_trans hidden = 1;

/*
 * setransd_open
 *
 * This function opens a socket to the setransd.
 * Returns:  on success, a file descriptor ( >= 0 ) to the socket
 *           on error, a negative value
 */
static int setransd_open(void)
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SETRANS_UNIX_SOCKET, sizeof(addr.sun_path));
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/* Returns: 0 on success, <0 on failure */
static int
send_request(int fd, uint32_t function, const char *data1, const char *data2)
{
	struct msghdr msgh;
	struct iovec iov[5];
	uint32_t data1_size;
	uint32_t data2_size;
	ssize_t count, expected;
	unsigned int i;

	if (fd < 0)
		return -1;

	if (!data1)
		data1 = "";
	if (!data2)
		data2 = "";

	data1_size = strlen(data1) + 1;
	data2_size = strlen(data2) + 1;

	iov[0].iov_base = &function;
	iov[0].iov_len = sizeof(function);
	iov[1].iov_base = &data1_size;
	iov[1].iov_len = sizeof(data1_size);
	iov[2].iov_base = &data2_size;
	iov[2].iov_len = sizeof(data2_size);
	iov[3].iov_base = (char *)data1;
	iov[3].iov_len = data1_size;
	iov[4].iov_base = (char *)data2;
	iov[4].iov_len = data2_size;
	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = iov;
	msgh.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

	expected = 0;
	for (i = 0; i < sizeof(iov) / sizeof(iov[0]); i++)
		expected += iov[i].iov_len;

	while (((count = sendmsg(fd, &msgh, 0)) < 0)
	       && (errno == EINTR)) ;
	if (count < 0 || count != expected)
		return -1;

	return 0;
}

/* Returns: 0 on success, <0 on failure */
static int
receive_response(int fd, uint32_t function, char **outdata, int32_t * ret_val)
{
	struct iovec resp_hdr[3];
	uint32_t func;
	uint32_t data_size;
	char *data;
	struct iovec resp_data;
	ssize_t count;

	if (fd < 0)
		return -1;

	resp_hdr[0].iov_base = &func;
	resp_hdr[0].iov_len = sizeof(func);
	resp_hdr[1].iov_base = &data_size;
	resp_hdr[1].iov_len = sizeof(data_size);
	resp_hdr[2].iov_base = ret_val;
	resp_hdr[2].iov_len = sizeof(*ret_val);

	while (((count = readv(fd, resp_hdr, 3)) < 0) && (errno == EINTR)) ;
	if (count != (sizeof(func) + sizeof(data_size) + sizeof(*ret_val))) {
		return -1;
	}

	if (func != function || !data_size || data_size > MAX_DATA_BUF) {
		return -1;
	}

	data = malloc(data_size);
	if (!data) {
		return -1;
	}

	resp_data.iov_base = data;
	resp_data.iov_len = data_size;

	while (((count = readv(fd, &resp_data, 1))) < 0 && (errno == EINTR)) ;
	if (count < 0 || (uint32_t) count != data_size ||
	    data[data_size - 1] != '\0') {
		free(data);
		return -1;
	}
	*outdata = data;
	return 0;
}

static int raw_to_trans_context(char *raw, char **transp)
{
	int ret;
	int32_t ret_val;
	int fd;

	*transp = NULL;

	fd = setransd_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, RAW_TO_TRANS_CONTEXT, raw, NULL);
	if (ret)
		goto out;

	ret = receive_response(fd, RAW_TO_TRANS_CONTEXT, transp, &ret_val);
	if (ret)
		goto out;

	ret = ret_val;
      out:
	close(fd);
	return ret;
}

static int trans_to_raw_context(char *trans, char **rawp)
{
	int ret;
	int32_t ret_val;
	int fd;

	*rawp = NULL;

	fd = setransd_open();
	if (fd < 0)
		return fd;
	ret = send_request(fd, TRANS_TO_RAW_CONTEXT, trans, NULL);
	if (ret)
		goto out;

	ret = receive_response(fd, TRANS_TO_RAW_CONTEXT, rawp, &ret_val);
	if (ret)
		goto out;

	ret = ret_val;
      out:
	close(fd);
	return ret;
}

hidden void fini_context_translations(void)
{
	if (cache_trans) {
		free(prev_r2t_trans);
		free(prev_r2t_raw);
		free(prev_t2r_trans);
		free(prev_t2r_raw);
	}
}

hidden int init_context_translations(void)
{
	int ret, fd;
	int32_t ret_val;
	char *out = NULL;

	mls_enabled = is_selinux_mls_enabled();
	if (!mls_enabled)
		return 0;

	fd = setransd_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, SETRANS_INIT, NULL, NULL);
	if (ret)
		goto out;

	ret = receive_response(fd, SETRANS_INIT, &out, &ret_val);
	free(out);
	if (!ret)
		ret = ret_val;
      out:
	close(fd);
	return ret;
}

int selinux_trans_to_raw_context(security_context_t trans,
				 security_context_t * rawp)
{
	if (!trans) {
		*rawp = NULL;
		return 0;
	}

	if (!mls_enabled) {
		*rawp = strdup(trans);
		goto out;
	}

	if (cache_trans) {
		if (prev_t2r_trans && strcmp(prev_t2r_trans, trans) == 0) {
			*rawp = strdup(prev_t2r_raw);
		} else {
			free(prev_t2r_trans);
			prev_t2r_trans = NULL;
			free(prev_t2r_raw);
			prev_t2r_raw = NULL;
			if (trans_to_raw_context(trans, rawp))
				*rawp = strdup(trans);
			if (*rawp) {
				prev_t2r_trans = strdup(trans);
				if (!prev_t2r_trans)
					goto out;
				prev_t2r_raw = strdup(*rawp);
				if (!prev_t2r_raw) {
					free(prev_t2r_trans);
					prev_t2r_trans = NULL;
				}
			}
		}
	} else if (trans_to_raw_context(trans, rawp))
		*rawp = strdup(trans);
      out:
	return *rawp ? 0 : -1;
}

hidden_def(selinux_trans_to_raw_context)

int selinux_raw_to_trans_context(security_context_t raw,
				 security_context_t * transp)
{
	if (!raw) {
		*transp = NULL;
		return 0;
	}

	if (!mls_enabled) {
		*transp = strdup(raw);
		goto out;
	}

	if (cache_trans) {
		if (prev_r2t_raw && strcmp(prev_r2t_raw, raw) == 0) {
			*transp = strdup(prev_r2t_trans);
		} else {
			free(prev_r2t_raw);
			prev_r2t_raw = NULL;
			free(prev_r2t_trans);
			prev_r2t_trans = NULL;
			if (raw_to_trans_context(raw, transp))
				*transp = strdup(raw);
			if (*transp) {
				prev_r2t_raw = strdup(raw);
				if (!prev_r2t_raw)
					goto out;
				prev_r2t_trans = strdup(*transp);
				if (!prev_r2t_trans) {
					free(prev_r2t_raw);
					prev_r2t_raw = NULL;
				}
			}
		}
	} else if (raw_to_trans_context(raw, transp))
		*transp = strdup(raw);
      out:
	return *transp ? 0 : -1;
}

hidden_def(selinux_raw_to_trans_context)
