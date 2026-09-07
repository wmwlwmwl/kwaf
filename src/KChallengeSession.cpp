#include "KChallengeSession.h"
#include "ksapi.h"
#include "klist.h"
#include "krbtree.h"
#include "KWaf.h"
volatile int32_t challeng_session_count = 0;
static KFIBER_MUTEX as_lock;
static KChallengeSession as_list;
static krb_tree *as_tree = NULL;
static int as_max_key = (int)time(NULL);
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
int create_session_number(char *url)
{
	int new_flag = 0;
	KChallengeSession *as = new KChallengeSession(url);
	as->expire_time = time(NULL) + 60;
	server_support->mutex->lock(as_lock);
	int key = as_max_key++;
	as->key = key;
	krb_node *node = rbtree_insert(as_tree, &as->key, &new_flag, anticc_session_key_cmp);
	assert(new_flag);
	node->data = as;
	klist_insert(&as_list, as);
	challeng_session_count++;
	server_support->mutex->unlock(as_lock);
	return key;
}
int anticc_session_number(int key)
{
	int number = -1;
	server_support->mutex->lock(as_lock);
	krb_node *node = rbtree_find(as_tree, &key, anticc_session_key_cmp);
	if (node) {
		KChallengeSession *as = (KChallengeSession *)node->data;
		number = as->number;
	}
	server_support->mutex->unlock(as_lock);
	return number;
}
char *anticc_session_verify(int key, int &number)
{
	char *url = NULL;
	server_support->mutex->lock(as_lock);
	krb_node *node = rbtree_find(as_tree, &key, anticc_session_key_cmp);
	if (node == NULL) {
		server_support->mutex->unlock(as_lock);
		return url;
	}
	KChallengeSession *as = (KChallengeSession *)node->data;
	number = as->number;
	rbtree_remove(as_tree, node);
	klist_remove(as);
	challeng_session_count--;
	server_support->mutex->unlock(as_lock);
	url = as->url;
	as->url = NULL;
	delete as;
	return url;
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
		assert(node);
		rbtree_remove(as_tree, node);
		klist_remove(as);
		delete as;
		challeng_session_count--;
	}
	server_support->mutex->unlock(as_lock);
}
