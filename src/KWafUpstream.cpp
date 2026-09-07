#include "KWafUpstream.h"
#include "kstring.h"
#include "KHttpField.h"
#include "KWafConfig.h"
#include "ksocket.h"
#include "KStringBuf.h"
#include "kmd5.h"
#include "KSequence.h"
#include "KDsoAutoBuffer.h"
#include <sstream>
#include <cerrno>
#include <cstdlib>
#include <vector>
#define KGL_WAF_COOKIE "kgl_cookie"

static KGL_RESULT get_string_variable(KREQUEST r, kgl_async_context *ctx,
	KGL_VAR type, const char *name, std::string &value)
{
	DWORD size = 0;
	KGL_RESULT result = ctx->f->get_variable(r, type, name, NULL, &size);
	if (result != KGL_EINSUFFICIENT_BUFFER) {
		value.clear();
		return result;
	}
	std::vector<char> buffer(size);
	result = ctx->f->get_variable(r, type, name, buffer.data(), &size);
	if (result == KGL_OK) {
		value.assign(buffer.data(), size);
	} else {
		value.clear();
	}
	return result;
}
KWafUpstream::KWafUpstream(KChallenge *challenge)
{
	this->challenge = challenge;
	challenge->AddRef();
}


KWafUpstream::~KWafUpstream()
{
	challenge->Release();
}

static void *create_ctx()
{
	//never goto here
	assert(false);
	return NULL;
}
static void free_ctx(void *ctx)
{
	KWafUpstream *waf_ctx = (KWafUpstream *)ctx;
	delete waf_ctx;
}
static KGL_RESULT check(KREQUEST rq, kgl_async_context *ctx)
{
	KWafUpstream *waf_ctx = (KWafUpstream *)ctx->module;
	return waf_ctx->check(rq, ctx);
}
KGL_RESULT KWafUpstream::check(KREQUEST r,kgl_async_context *ctx)
{
	char md5buf[33];
	std::string ips;
	std::string path;
	std::string param;
	if (get_string_variable(r, ctx, KGL_VAR_REMOTE_ADDR, NULL, ips) != KGL_OK ||
		get_string_variable(r, ctx, KGL_VAR_PATH_INFO, NULL, path) != KGL_OK) {
		return KGL_NEXT;
	}
	KGL_RESULT ret = get_string_variable(r, ctx, KGL_VAR_QUERY_STRING, NULL, param);
	if (ret != KGL_OK && ret != KGL_ENO_DATA) {
		return KGL_NEXT;
	}
	if (ret == KGL_OK) {
		std::string prefix(waf_config.cc_key);
		prefix += '=';
		size_t key_pos = std::string::npos;
		if (param.compare(0, prefix.size(), prefix) == 0) {
			key_pos = 0;
		} else {
			std::string marker = "&" + prefix;
			size_t marker_pos = param.find(marker);
			if (marker_pos != std::string::npos) {
				key_pos = marker_pos + 1;
			}
		}
		if (key_pos != std::string::npos) {
			size_t value_pos = key_pos + prefix.size();
			size_t value_end = param.find('&', value_pos);
			std::string cc_key = param.substr(value_pos, value_end - value_pos);
			if (key_pos == 0) {
				param.erase(0, value_end == std::string::npos ? param.size() : value_end + 1);
			} else {
				size_t erase_pos = key_pos - 1;
				param.erase(erase_pos, value_end == std::string::npos ? std::string::npos : value_end - erase_pos);
			}

			ctx->f->support_function(r, ctx->cn, KD_REQ_REWRITE_PARAM, (void *)param.c_str(), NULL);
			int cc_flag = 0;
			if (CheckCCKey(r, ctx, ips.c_str(), cc_key.c_str(), cc_flag)) {
				if (!KBIT_TEST(cc_flag, ANTICC_FIX_URL)) {
					return KGL_NEXT;
				}
				//再重定向一次修复url
				ctx->out->f->write_status(ctx->out->ctx, 302);
				std::stringstream  fix_url;
				
				fix_url << path;
				if (!param.empty()) {
					fix_url << "?" << param;
				}
				std::string location = fix_url.str();
				KGL_RESULT header_result = ctx->out->f->write_unknow_header(ctx->out->ctx, kgl_expand_string("Location"), location.c_str(), (hlen_t)location.size());
				if (header_result != KGL_OK) {
					return header_result;
				}
				kgl_response_body body;
				auto result = ctx->out->f->write_header_finish(ctx->out->ctx, 0, &body);
				if (result != KGL_OK) {
					return result;
				}
				return body.f->close(body.ctx, KGL_OK);
			}
		}
	}

	if (challenge->wl && ctx->f->support_function(r, ctx->cn, KD_REQ_CHECK_WHITE_LIST, (void *)ips.c_str(),(void **)&challenge->flush)==KGL_OK) {
		//白名单
		return KGL_NEXT;
	}
	std::string host;
	get_string_variable(r, ctx, KGL_VAR_SERVER_NAME, NULL, host);
	std::string rate_target = host;
	rate_target += '\n';
	rate_target += path;
	if (!challenge->shouldChallenge(rate_target.c_str())) {
		return KGL_NEXT;
	}
	KStringBuf r_url;
	KStringBuf id;
	unsigned seq = sequence.getNext();
	time_t now_time = time(NULL);
	KDsoAutoBuffer new_request(r);
	int cc_flag = 0;
	if (challenge->wl) {
		KBIT_SET(cc_flag, ANTICC_WHITE_LIST);
	}
	if (challenge->fix_url) {
		KBIT_SET(cc_flag, ANTICC_FIX_URL);
	}
	id.add(cc_flag, "%d");
	r_url.add(cc_flag, "%d");
	r_url << ips;
	r_url.write_all(waf_config.cc_salt, waf_config.cc_salt_len);
	r_url << (INT64)now_time << "_" << seq;
	KMD5(r_url.c_str(), r_url.size(), md5buf);
	id.write_all(md5buf, 32);
	id << (INT64)now_time << "_" << seq;
	ctx->out->f->write_status(ctx->out->ctx,  challenge->status_code);
	
	KChallengeHeader *header = challenge->header;

	KChallengeBuffer *buffer = challenge->body;
	KAntiRefreshParserContext cc_ctx;
	KStringBuf new_url;
	new_url << path;
	if (!param.empty()) {
		new_url << "?" << param << "&";
	} else {
		new_url << "?";
	}
	new_url << waf_config.cc_key << "=" << id.c_str();
	while (header) {
		KGL_RESULT header_result;
		if (header->val == NULL) {
			header_result = ctx->out->f->write_unknow_header(ctx->out->ctx, header->attr, header->attr_len, "", 0);
		} else if (header->val->next == NULL && header->val->type == CC_BUFFER_STRING) {
			assert(header->val->buf);
			header_result = ctx->out->f->write_unknow_header(ctx->out->ctx, header->attr, header->attr_len, header->val->buf, header->val->len);
		} else {
			KDsoAutoBuffer tmp_buffer(NULL);
			header->process(tmp_buffer, new_url, &cc_ctx);
			kbuf *buf = tmp_buffer.getHead();
			if (buf == NULL) {
				header_result = ctx->out->f->write_unknow_header(ctx->out->ctx, header->attr, header->attr_len, "", 0);
			} else if (buf->next == NULL) {
				header_result = ctx->out->f->write_unknow_header(ctx->out->ctx, header->attr, header->attr_len, buf->data, buf->used);
			} else {
				KStringBuf val;
				while (buf) {
					val.write_all(buf->data, buf->used);
					buf = buf->next;
				}
				header_result = ctx->out->f->write_unknow_header(ctx->out->ctx, header->attr, header->attr_len, val.buf(), val.size());
			}
		}
		if (header_result != KGL_OK) {
			return header_result;
		}
		header = header->next;
	}
	while (buffer) {
		buffer->process(new_request, new_url, &cc_ctx);
		buffer = buffer->next;
	}
	int bc = new_request.getLen();
	auto buf = new_request.getHead();
	kgl_response_body body;
	auto result = ctx->out->f->write_header_finish(ctx->out->ctx, (int64_t)new_request.getLen(), &body);
	if (result != KGL_OK) {
		return result;
	}
	std::string method;
	if (get_string_variable(r, ctx, KGL_VAR_REQUEST_METHOD, NULL, method) == KGL_OK && method == "HEAD") {
		return body.f->close(body.ctx, KGL_OK);
	}
	return body.f->close(body.ctx, body.f->writev(body.ctx, buf,bc));
}
bool KWafUpstream::CheckCCKey(KREQUEST r, kgl_async_context *ctx, const char *ips, const char *cc_key, int &cc_flag)
{
	if (!cc_key) {
		return false;
	}

	char md5buf[33];
	//printf("cc_key=%s\n",cc_key);
	size_t key_len = strlen(cc_key);
	if (key_len < 36 || cc_key[0] < '0' || cc_key[0] > '9') {
		return false;
	}
	KStringBuf s;
	errno = 0;
	char *time_end = NULL;
	long long issued_at = strtoll(cc_key + 33, &time_end, 10);
	if (errno != 0 || time_end == cc_key + 33 || *time_end != '_' || issued_at < 0) {
		return false;
	}
	const char *seq = time_end + 1;
	if (*seq == '\0') {
		return false;
	}
	while (*seq) {
		if (*seq < '0' || *seq > '9') {
			return false;
		}
		++seq;
	}
	long long now = (long long)time(NULL);
	long long go_time = now - issued_at;
	if (go_time < MAX_ATTACK_ALIVE_TIME && go_time >= 0) {//时间有效
		s << *cc_key << ips;
		s.write_all(waf_config.cc_salt, waf_config.cc_salt_len);
		s << cc_key + 33;
		KMD5(s.c_str(), s.size(), md5buf);
		//		printf("*********s=%s,md5=%s\n",s.str().c_str(),md5buf);
		if (memcmp(cc_key + 1, md5buf, 32) == 0) {//是正常用户
			//printf("这是正常用户访问\n");
			cc_flag = *cc_key - '0';
			if (KBIT_TEST(cc_flag, ANTICC_WHITE_LIST)) {
				ctx->f->support_function(r, ctx->cn, KD_REQ_ADD_WHITE_LIST, (void *)ips, NULL);
			}
			return true;
		}
	}
	return false;
}
static kgl_upstream waf_upstream = {
	sizeof(kgl_upstream),
	KGL_UPSTREAM_BEFORE_CACHE|KGL_UPSTREAM_FILTER,
	"waf",
	create_ctx,
	free_ctx,
	check,
	NULL
};
bool create_waf_upstream(KREQUEST r, kgl_access_context *ctx, KChallenge *c)
{
	KWafUpstream *us = new KWafUpstream(c);
	if (ctx->f->support_function(r, ctx->cn, KF_REQ_UPSTREAM, &waf_upstream, (void **)&us) != KGL_OK) {
		delete us;
		return false;
	}
	return true;
}
