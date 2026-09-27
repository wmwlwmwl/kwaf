#include "KChallengeSession.h"
#include "ksapi.h"
#include "klist.h"
#include "krbtree.h"
#include "KWaf.h"
#include <limits.h>
#include <random>
volatile int32_t challeng_session_count = 0;
static KFIBER_MUTEX as_lock;
static KChallengeSession as_list;
static krb_tree *as_tree = NULL;
static uint32_t as_next_key = (uint32_t)time(NULL);
static const int max_challenge_sessions = 100000;

static uint32_t challenge_random()
{
	static thread_local std::mt19937 generator([]() {
		uint32_t values[5] = { 0, 0, 0, 0, (uint32_t)time(NULL) };
		try {
			std::random_device source;
			for (int i = 0; i < 4; ++i) {
				values[i] = source();
			}
		} catch (...) {
			values[0] = (uint32_t)(uintptr_t)&values;
			values[1] = (uint32_t)clock();
			values[2] = values[0] ^ values[4] ^ 0x9e3779b9u;
			values[3] = values[1] ^ 0x85ebca6bu;
		}
		std::seed_seq seed(values, values + 5);
		return std::mt19937(seed);
	}());
	return generator();
}

KChallengeSession::KChallengeSession(char *session_url)
{
	key = 0;
	number = 1000 + (int)(challenge_random() % 9000);
	image_seed = challenge_random();
	url = session_url;
	expire_time = 0;
	next = NULL;
	prev = NULL;
}

KChallengeSession::KChallengeSession()
{
	memset(this, 0, sizeof(KChallengeSession));
}

KChallengeSession::~KChallengeSession()
{
	if (url) {
		free(url);
	}
}
int get_challenge_session_count()
{
	int count;
	server_support->mutex->lock(as_lock);
	count = challeng_session_count;
	server_support->mutex->unlock(as_lock);
	return count;
}
static int anticc_session_key_cmp(const void *key1, const void *key2)
{
	int left = *(const int *)key1;
	int right = *(const int *)key2;
	return left < right ? -1 : (left > right ? 1 : 0);
}
void init_anticc_session()
{
	klist_init(&as_list);
	as_tree = rbtree_create();
	as_lock = server_support->mutex->init(1);
}

static void remove_session_locked(krb_node *node, KChallengeSession *session)
{
	rbtree_remove(as_tree, node);
	klist_remove(session);
	challeng_session_count--;
	delete session;
}

static void evict_oldest_session_locked()
{
	KChallengeSession *session = klist_head(&as_list);
	if (session == &as_list) {
		return;
	}
	krb_node *node = rbtree_find(as_tree, &session->key, anticc_session_key_cmp);
	if (node) {
		remove_session_locked(node, session);
	} else {
		klist_remove(session);
		challeng_session_count--;
		delete session;
	}
}

int create_session_number(char *url)
{
	int new_flag = 0;
	KChallengeSession *as = new KChallengeSession(url);
	as->expire_time = time(NULL) + 60;
	server_support->mutex->lock(as_lock);
	while (challeng_session_count >= max_challenge_sessions) {
		evict_oldest_session_locked();
	}
	for (;;) {
		int key = (int)(as_next_key++ & INT_MAX);
		if (key != 0 && rbtree_find(as_tree, &key, anticc_session_key_cmp) == NULL) {
			as->key = key;
			break;
		}
	}
	krb_node *node = rbtree_insert(as_tree, &as->key, &new_flag, anticc_session_key_cmp);
	if (!new_flag || node == NULL) {
		server_support->mutex->unlock(as_lock);
		delete as;
		return -1;
	}
	node->data = as;
	klist_insert(&as_list, as);
	challeng_session_count++;
	int key = as->key;
	server_support->mutex->unlock(as_lock);
	return key;
}
bool anticc_session_image(int key, int *number, uint32_t *image_seed)
{
	bool found = false;
	server_support->mutex->lock(as_lock);
	krb_node *node = rbtree_find(as_tree, &key, anticc_session_key_cmp);
	if (node) {
		KChallengeSession *as = (KChallengeSession *)node->data;
		if (as->expire_time > time(NULL)) {
			*number = as->number;
			*image_seed = as->image_seed;
			found = true;
		} else {
			remove_session_locked(node, as);
		}
	}
	server_support->mutex->unlock(as_lock);
	return found;
}
anticc_session_verify_result anticc_session_verify(int key, int number, char **url)
{
	*url = NULL;
	server_support->mutex->lock(as_lock);
	krb_node *node = rbtree_find(as_tree, &key, anticc_session_key_cmp);
	if (node == NULL) {
		server_support->mutex->unlock(as_lock);
		return ANTICC_SESSION_NOT_FOUND;
	}
	KChallengeSession *as = (KChallengeSession *)node->data;
	if (as->expire_time <= time(NULL)) {
		remove_session_locked(node, as);
		server_support->mutex->unlock(as_lock);
		return ANTICC_SESSION_NOT_FOUND;
	}
	if (as->number != number) {
		remove_session_locked(node, as);
		server_support->mutex->unlock(as_lock);
		return ANTICC_SESSION_INCORRECT;
	}
	*url = as->url;
	as->url = NULL;
	remove_session_locked(node, as);
	server_support->mutex->unlock(as_lock);
	return ANTICC_SESSION_VERIFIED;
}
void anticc_session_flush(time_t now_time)
{
	server_support->mutex->lock(as_lock);
	for (;;) {
		KChallengeSession *as = klist_head(&as_list);
		if (as == &as_list) {
			break;
		}
		if (as->expire_time > now_time) {
			break;
		}
		krb_node *node = rbtree_find(as_tree, &as->key, anticc_session_key_cmp);
		if (node) {
			remove_session_locked(node, as);
		} else {
			klist_remove(as);
			challeng_session_count--;
			delete as;
		}
	}
	server_support->mutex->unlock(as_lock);
}
