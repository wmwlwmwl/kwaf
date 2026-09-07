#ifndef KGL_WAF_H
#define KGL_WAF_H
#include "ksapi.h"
#include "kmalloc.h"
#include <string>
#include "KWafConfig.h"
#include "KChallenge.h"

class KWaf: public KChallengeConfig
{
public:
	KWaf();
	~KWaf();
	KGL_RESULT build(kgl_access_build *build_ctx, uint32_t build_type);
	KGL_RESULT parse(kgl_access_parse_config *parse_ctx);
	uint32_t process(KREQUEST r, kgl_access_context *ctx, DWORD notify);
private:
	std::string msg;
	KChallenge *challenge;
	KFIBER_MUTEX challenge_lock;
};
extern kgl_dso_version *server_support;
#endif
