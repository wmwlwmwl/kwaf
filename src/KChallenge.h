#ifndef KCHALLENGE_H
#define KCHALLENGE_H
#include "KChallengeBuffer.h"
#include "KHttpBufferParser.h"
#include "KTargetRate.h"
#define CC_BUFFER_STRING    0
#define CC_BUFFER_URL       1
#define CC_BUFFER_MURL      2
#define CC_BUFFER_REVERT    3
#define CC_BUFFER_SB        4
#define CC_BUFFER_SC_KEY    5
#define CC_BUFFER_PROXY     6

struct anti_cc_model
{
	const char *name;
	const char *content;
};
extern anti_cc_model anti_cc_models[7];
class KChallengeConfig
{
public:
	KChallengeConfig()
	{
		memset(this, 0, sizeof(*this));
	}
	int request;
	int second;
	bool wl;
	bool fix_url;
	bool skip_cache;
	bool flush;
	float rate;
};
class KChallengeParser
{
public:
	KChallengeParser()
	{
		body = NULL;
		last = NULL;
	}
	~KChallengeParser()
	{
		destroy();
	}
	void parse(char *msg)
	{
		destroy();
		char *hot = msg;
		for (;;) {
			char *start = strstr(hot, "{{");
			if (start == NULL) {
				break;
			}
			char *end = strstr(start, "}}");
			if (end == NULL) {
				break;
			}
			addBuffer(hot, (int)(start - hot));
			*end = '\0';
			addCommand(start + 2);
			hot = end + 2;
		}
		addBuffer(hot, (int)strlen(hot));
	}
	KChallengeBuffer *stealBuffer()
	{
		KChallengeBuffer *b = body;
		body = NULL;
		return b;
	}
private:
	void addBuffer(char *msg, int len)
	{
		if (len <= 0) {
			return;
		}
		KChallengeBuffer *buf = new KChallengeBuffer;
		buf->type = CC_BUFFER_STRING;
		buf->buf = (char *)malloc(len);
		kgl_memcpy(buf->buf, msg, len);
		buf->len = len;
		addBuffer(buf);
	}
	void addCommand(char *cmd)
	{
		KChallengeBuffer *buf = new KChallengeBuffer;
		buf->buf = NULL;
		buf->len = 0;
		if (strcasecmp(cmd, "url") == 0) {
			buf->type = CC_BUFFER_URL;
		} else if (strcasecmp(cmd, "murl") == 0) {
			buf->type = CC_BUFFER_MURL;
		} else if (strncasecmp(cmd, "revert:", 7) == 0) {
			buf->type = CC_BUFFER_REVERT;
			buf->buf = strdup(cmd + 7);
		} else if (strncasecmp(cmd, "sb:", 3) == 0) {
			buf->type = CC_BUFFER_SB;
			buf->buf = strdup(cmd + 3);
		} else if (strcasecmp(cmd, "session_key") == 0) {
			buf->type = CC_BUFFER_SC_KEY;
		} else {
			delete buf;
			return;
		}
		addBuffer(buf);
	}
	void addBuffer(KChallengeBuffer *buf)
	{
		buf->next = NULL;
		if (last) {
			last->next = buf;
		} else {
			body = buf;
		}
		last = buf;
	}
	void destroy()
	{
		while (body) {
			KChallengeBuffer *tmp = body->next;
			delete body;
			body = tmp;
		}
		last = NULL;
	}
	KChallengeBuffer *body;
	KChallengeBuffer *last;
};

class KChallengeHeader
{
public:
	KChallengeHeader()
	{
		memset(this, 0, sizeof(KChallengeHeader));
	}
	~KChallengeHeader()
	{
		if (attr) {
			free(attr);
		}
		while (val) {
			KChallengeBuffer *n = val->next;
			delete val;
			val = n;
		}
	}
	void parse(KHttpHeader *header)
	{
		kgl_str_t result;
		kgl_get_header_name(header, &result);
		this->attr = kgl_strndup(result.data, result.len);
		this->attr_len = (hlen_t)result.len;
		KChallengeParser cc_parser;
		char* buf = kgl_strndup(header->buf + header->val_offset, header->val_len);
		cc_parser.parse(buf);
		xfree(buf);
		val = cc_parser.stealBuffer();
	}
	void process(KDsoAutoBuffer &new_request, KStringBuf &new_url, KAntiRefreshParserContext *ctx)
	{
		KChallengeBuffer *hot_val = val;
		while (hot_val) {
			hot_val->process(new_request, new_url, ctx);
			hot_val = hot_val->next;
		}
	}
	char *attr;
	hlen_t attr_len;
	KChallengeBuffer *val;
	KChallengeHeader *next;
};

class KChallenge : public KChallengeConfig
{
public:
	KChallenge()
	{
		header = NULL;
		body = NULL;
		request = 0;
		rate = 0;
		wl = false;
		fix_url = false;
		status_code = 200;
		ref = 1;
	}
	void Release()
	{
		if (katom_dec((void *)&ref) == 0) {
			delete this;
		}
	}
	void AddRef()
	{
		katom_inc((void *)&ref);
	}
	bool shouldChallenge(const char *target)
	{
		if (request <= 0 || second <= 0 || target == NULL) {
			return false;
		}
		time_t now = time(NULL);
		target_rate.flush(now, second);
		int max_request = request;
		int elapsed = 0;
		return target_rate.getRate(target, max_request, elapsed, true) && elapsed < second;
	}
	void parse(const char *msg)
	{
		destroy();
		if (*msg == '@') {
			this->body = new KChallengeBuffer();
			this->body->type = CC_BUFFER_PROXY;
			this->body->buf = strdup(msg + 1);
			this->body->len = (u_short)(strlen(this->body->buf));
			return;
		}
		KWriteBackParser parser;
		int len = (int)strlen(msg);
		char *buf = (char *)malloc(len + 1);
		kgl_memcpy(buf, msg, len + 1);
		char *hot = buf;
		char* end = hot + len;
		parser.Parse(&hot, end);
		status_code = parser.status_code;
#ifdef ENABLE_ANTICC_KEEP_ALIVE
		keep_alive = hook.keep_alive;
#endif
		KHttpHeader *http_header = parser.steal_header();
		KHttpHeader *hot_header = http_header;
		KChallengeHeader *last_header = NULL;
		while (hot_header) {
			KChallengeHeader *t = new KChallengeHeader;
			t->parse(hot_header);
			if (last_header) {
				last_header->next = t;
			} else {
				header = t;
			}
			last_header = t;
			hot_header = hot_header->next;
		}
		free_header_list(http_header);
		if (len > 0) {
			KChallengeParser body_parser;
			body_parser.parse(hot);
			body = body_parser.stealBuffer();
		}
		xfree(buf);
	}
	KChallengeHeader *header;
	KChallengeBuffer *body;
	uint16_t status_code;
	float rate;
private:
	volatile int32_t ref;
	KTargetRate target_rate;
	void destroy()
	{
		while (body) {
			KChallengeBuffer *tmp = body->next;
			delete body;
			body = tmp;
		}
		while (header) {
			KChallengeHeader *n = header->next;
			delete header;
			header = n;
		}
	}
	~KChallenge()
	{
		destroy();
	}
};
#endif
