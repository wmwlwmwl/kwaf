#include "KWafSession.h"
#include "KChallengeSession.h"
#include <cerrno>
#include <climits>
#include <cstdlib>

// Returns 1 for a valid value, 0 when absent, and -1 when malformed.
static int get_int_param(const char *query, const char *name, int *value)
{
	size_t name_len = strlen(name);
	const char *p = query;
	while (p && *p) {
		const char *end = strchr(p, '&');
		size_t len = end ? (size_t)(end - p) : strlen(p);
		if (len > name_len + 1 && memcmp(p, name, name_len) == 0 && p[name_len] == '=') {
			errno = 0;
			char *number_end = NULL;
			long parsed = strtol(p + name_len + 1, &number_end, 10);
			if (errno != 0 || number_end != p + len || parsed < INT_MIN || parsed > INT_MAX) {
				return -1;
			}
			*value = (int)parsed;
			return 1;
		}
		p = end ? end + 1 : NULL;
	}
	return 0;
}

uint32_t KWafSession::process(KREQUEST r, kgl_access_context *ctx, DWORD notify)
{
	char param[512];
	DWORD param_len = sizeof(param) - 1;
	if (KGL_OK != ctx->f->get_variable(r, KGL_VAR_QUERY_STRING, NULL, param, &param_len)) {
		return KF_STATUS_REQ_FALSE;
	}
	int key;
	if (get_int_param(param, "k", &key) != 1) {
		return KF_STATUS_REQ_FALSE;
	}
	int val;
	int value_result = get_int_param(param, "v", &val);
	if (value_result < 0) {
		return KF_STATUS_REQ_FALSE;
	}
	if (value_result == 0) {
		//get security number
		int number = anticc_session_number(key);
		if (number == -1) {
			return KF_STATUS_REQ_FALSE;
		}
		memset(param, 0, sizeof(param));
		snprintf(param, 16, "v=%d", number);
		ctx->f->support_function(r, ctx->cn, KD_REQ_REWRITE_PARAM, param, NULL);
		return KF_STATUS_REQ_TRUE;
	}
	int secury_num = -1;
	char *url = anticc_session_verify(key, secury_num);
	if (url == NULL) {
		return KF_STATUS_REQ_FALSE;
	}
	char *p = strchr(url, '?');
	if (p) {
		if (secury_num == val) {
			ctx->f->support_function(r, ctx->cn, KD_REQ_REWRITE_URL, url, NULL);
		}
	}
	free(url);
	return KF_STATUS_REQ_FALSE;
}
