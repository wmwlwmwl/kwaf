#ifndef KWAFUPSTREAM_H_99
#define KWAFUPSTREAM_H_99
#include "ksapi.h"
#include "KChallenge.h"
class KWafConfig;
class KWafUpstream
{
public:
	KWafUpstream(KChallenge *waf_config);
	KGL_RESULT check(KREQUEST r, kgl_async_context *ctx);
	~KWafUpstream();
private:
	bool CheckCCKey(KREQUEST r, kgl_async_context *ctx, const char *ips, const char *cc_key, int &cc_flag);
	KChallenge *challenge;
};

bool create_waf_upstream(KREQUEST r, kgl_access_context *ctx, KChallenge *c);
#endif
