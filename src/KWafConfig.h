#ifndef KWAFCONFIG_H_99
#define KWAFCONFIG_H_99
#include <string>
#include "kmalloc.h"
#define ANTICC_WHITE_LIST 1
#define ANTICC_FIX_URL    2
#define ANTICC_KEEP_ALIVE 4

#define MAX_ATTACK_ALIVE_TIME  60
#define SAFE_STRCPY(s,s1)   do {memset(s,0,sizeof(s));strncpy(s,s1,sizeof(s)-1);}while(0)
class KWafConfig {
public:
	KWafConfig()
	{
		memset(this, 0, sizeof(*this));
	}
	char cc_salt[16];
	int cc_salt_len;

	int cc_key_len;
	char cc_key[16];

	char first_cc_str[24];
	char not_first_cc_str[24];
	void set_cc_key(const char *cc_key)
	{
		SAFE_STRCPY(this->cc_key, cc_key);
		cc_key_len = (int)strlen(this->cc_key);
		SAFE_STRCPY(this->first_cc_str, this->cc_key);
		this->first_cc_str[cc_key_len + 1] = '\0';
		this->first_cc_str[cc_key_len] = '=';
		memset(this->not_first_cc_str, 0, sizeof(this->not_first_cc_str));
		this->not_first_cc_str[0] = '&';
		kgl_memcpy(this->not_first_cc_str + 1, this->cc_key, cc_key_len);
		this->not_first_cc_str[cc_key_len + 1] = '=';
	}
	void set_cc_salt(const char *cc_salt) {
		SAFE_STRCPY(this->cc_salt, cc_salt);
		cc_salt_len = (int)strlen(this->cc_salt);
	}
	~KWafConfig()
	{

	}
};
extern KWafConfig waf_config;
#endif
