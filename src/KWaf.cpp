#include <sstream>
#include "kstring.h"
#include "KWaf.h"
#include "KWafUpstream.h"
#include "ksocket.h"
#include "KChallenge.h"
#include "KXml.h"

KWaf::KWaf() {
	challenge = NULL;
	challenge_lock = server_support->mutex->init(1);
}


KWaf::~KWaf() {
	server_support->mutex->lock(challenge_lock);
	KChallenge *old_challenge = challenge;
	challenge = NULL;
	server_support->mutex->unlock(challenge_lock);
	if (old_challenge) {
		old_challenge->Release();
	}
	server_support->mutex->destroy(challenge_lock);
}
KGL_RESULT KWaf::build(kgl_access_build* build_ctx, uint32_t build_type) {
	std::stringstream s;
	int total_cc_model = sizeof(anti_cc_models) / sizeof(anti_cc_model);
	switch (build_type) {
	case KF_ACCESS_BUILD_SHORT:
		s << "request=" << request << ",second=" << second;
		build_ctx->write_string(build_ctx->cn, s.str().c_str(), (int)s.str().size(), 0);
		return KGL_OK;
	case KF_ACCESS_BUILD_HTML:
		s << "request:<input name='request' size='4' value='";
		s << request;
		s << "'> second:<input name='second' size='4' value='";
		s << second;
		s << "'>";
		s << "<input type='checkbox' name='wl' value='1' ";
		if (wl) {
			s << "checked";
		}
		s << ">white list";
		s << "<input type='checkbox' name='fix_url' value='1' ";
		if (fix_url) {
			s << "checked";
		}
		s << ">fix_url";
		s << "<input type='checkbox' name='flush' value='1' ";
		if (flush) {
			s << "checked";
		}
		s << ">flush";
		s << "<br>msg:<textarea name='_' rows='6' cols='50'>";
		s << msg;
		s << "</textarea>";
		s << "<script language='javascript'>\r\n\
			 var cc_model=new Array(";

		for (int i = 0; i < total_cc_model; i++) {
			if (i > 0) {
				s << ",";
			}
			s << "'" << anti_cc_models[i].content << "'";
		}
		s << ");\
			 function set_cc_model(m){\r\n\
			 if(m==0) return;\
			 accessaddform._.value=cc_model[m-1];\r\n\
			}\r\n\
			</script>\r\n<br>\
			preset msg:<select onchange='set_cc_model(this.options[this.selectedIndex].value)'>";
		s << "<option value='0'>--select preset msg--</option>";
		for (int i = 0; i < total_cc_model; i++) {
			s << "<option value='" << i + 1 << "'>" << anti_cc_models[i].name << "</option>";
		}
		s << "</select>";
		build_ctx->write_string(build_ctx->cn, s.str().c_str(), (int)s.str().size(), 0);
		break;
	default:
		return KGL_ENOT_SUPPORT;
	}
	return KGL_OK;
}
KGL_RESULT KWaf::parse(kgl_access_parse_config* parse_ctx) {
	const char* val;

	val = parse_ctx->body->get_value(parse_ctx->cn, "msg");
	if (val) {
		msg = val;
	}
	request = (int)parse_ctx->body->get_int(parse_ctx->cn, "request");
	second = (int)parse_ctx->body->get_int(parse_ctx->cn, "second");
	wl = parse_ctx->body->get_int(parse_ctx->cn, "wl") == 1;
	fix_url = parse_ctx->body->get_int(parse_ctx->cn, "fix_url") == 1;
	skip_cache = parse_ctx->body->get_int(parse_ctx->cn, "skip_cache") == 1;
	flush = parse_ctx->body->get_int(parse_ctx->cn, "flush") == 1;
	rate = 0;
	if (second > 0) {
		rate = (float)request / (float)second;
	}
	val = parse_ctx->body->get_text(parse_ctx->cn);
	if (val && *val) {
		msg = val;
	}
	KChallenge* challenge = new KChallenge;
	memcpy(static_cast<KChallengeConfig*>(challenge), static_cast<KChallengeConfig*>(this), sizeof(KChallengeConfig));
	challenge->parse(msg.c_str());
	server_support->mutex->lock(challenge_lock);
	KChallenge *old_challenge = this->challenge;
	this->challenge = challenge;
	server_support->mutex->unlock(challenge_lock);
	if (old_challenge) {
		old_challenge->Release();
	}
	return KGL_OK;
}
uint32_t KWaf::process(KREQUEST r, kgl_access_context* ctx, DWORD notify) {
	KChallenge *current = NULL;
	server_support->mutex->lock(challenge_lock);
	if (challenge) {
		challenge->AddRef();
		current = challenge;
	}
	server_support->mutex->unlock(challenge_lock);
	if (current) {
		char buf[32];
		buf[0] = '\0';
		DWORD size = sizeof(buf);
		ctx->f->get_variable(r, KGL_VAR_SERVER_PROTOCOL, NULL, buf, &size);
		if (strncmp(buf, kgl_expand_string("HTTP")) != 0) {
			current->Release();
			return KF_STATUS_REQ_FALSE;
		}
		bool registered = create_waf_upstream(r, ctx, current);
		current->Release();
		if (!registered) {
			return KF_STATUS_REQ_FALSE;
		}
	}
	return KF_STATUS_REQ_TRUE;
}
