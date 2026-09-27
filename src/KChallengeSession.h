#ifndef WAF_DSO_KCHALLENGE_SESSION_H
#define WAF_DSO_KCHALLENGE_SESSION_H
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
class KChallengeSession
{
public:
	explicit KChallengeSession(char *url);
	KChallengeSession();
	~KChallengeSession();
	int key;
	int number;
	uint32_t image_seed;
	char *url;
	time_t expire_time;
	KChallengeSession *next;
	KChallengeSession *prev;
};
enum anticc_session_verify_result {
	ANTICC_SESSION_NOT_FOUND,
	ANTICC_SESSION_INCORRECT,
	ANTICC_SESSION_VERIFIED
};
int get_challenge_session_count();
int create_session_number(char *url);
bool anticc_session_image(int key, int *number, uint32_t *image_seed);
anticc_session_verify_result anticc_session_verify(int key, int number, char **url);
void anticc_session_flush(time_t now_time);
void init_anticc_session();
#endif
