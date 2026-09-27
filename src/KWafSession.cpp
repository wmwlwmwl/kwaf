#include "KWafSession.h"
#include "KChallengeSession.h"
#include "KCaptchaImage.h"
#include "KAccessDsoSupport.h"
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <vector>

static bool set_response_header(KREQUEST r, kgl_access_context *ctx,
	const char *name, const char *value)
{
	return ctx->f->response_header(r, ctx->cn, name, (hlen_t)strlen(name),
		value, (hlen_t)strlen(value)) == KGL_OK;
}

static uint32_t write_captcha_response(KREQUEST r, kgl_access_context *ctx,
	uint16_t status, const char *content_type, const unsigned char *data, size_t size,
	const char *location = NULL)
{
	char status_text[8];
	snprintf(status_text, sizeof(status_text), "%u", (unsigned)status);
	if (!set_response_header(r, ctx, "Status", status_text) ||
		!set_response_header(r, ctx, "Content-Type", content_type) ||
		!set_response_header(r, ctx, "Cache-Control", "no-cache, no-store, must-revalidate") ||
		!set_response_header(r, ctx, "Pragma", "no-cache") ||
		!set_response_header(r, ctx, "X-Content-Type-Options", "nosniff")) {
		return KF_STATUS_REQ_FALSE;
	}
	if (location && !set_response_header(r, ctx, "Location", location)) {
		return KF_STATUS_REQ_FALSE;
	}
	KAccessContext *access_context = (KAccessContext *)ctx->cn;
	KAutoBuffer *buffer = access_context->GetBuffer((KHttpRequest *)r);
	if (size > 0 && buffer->write_all((const char *)data, (int)size) != KGL_OK) {
		return KF_STATUS_REQ_FALSE;
	}
	return KF_STATUS_REQ_TRUE | KF_STATUS_REQ_FINISHED;
}

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
		int number = 0;
		uint32_t image_seed = 0;
		if (!anticc_session_image(key, &number, &image_seed)) {
			return KF_STATUS_REQ_FALSE;
		}
		std::vector<unsigned char> image;
		if (!build_captcha_png(number, image_seed, image)) {
			return KF_STATUS_REQ_FALSE;
		}
		return write_captcha_response(r, ctx, 200, "image/png", image.data(), image.size());
	}
	char *url = NULL;
	anticc_session_verify_result verify_result = anticc_session_verify(key, val, &url);
	if (verify_result == ANTICC_SESSION_NOT_FOUND) {
		return KF_STATUS_REQ_FALSE;
	}
	if (verify_result == ANTICC_SESSION_VERIFIED) {
		if (url == NULL || url[0] != '/' || strpbrk(url, "\r\n") != NULL) {
			free(url);
			return KF_STATUS_REQ_FALSE;
		}
		static const unsigned char redirect_body[] = "Redirecting";
		uint32_t result = write_captcha_response(r, ctx, 302, "text/plain; charset=utf-8",
			redirect_body, sizeof(redirect_body) - 1, url);
		free(url);
		return result;
	}
	// Keep the legacy behavior for an incorrect answer. Returning false lets
	// the vhost anti_cc rule render its configured challenge page and create a
	// fresh session instead of replacing it with an extension-owned error page.
	return KF_STATUS_REQ_FALSE;
}
