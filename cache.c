#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <mosquitto.h>
#include "userdata.h"
#include "cache.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "uthash.h"
#include "log.h"

static unsigned int sha_hash(const char *data, size_t size, unsigned char *out)
{
	unsigned int md_len = -1;
	const EVP_MD *md = EVP_get_digestbyname("SHA1");

	if (md != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
#else
		EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
#endif
		EVP_MD_CTX_init(mdctx);
		EVP_DigestInit_ex(mdctx, md, NULL);
		EVP_DigestUpdate(mdctx, data, size);
		EVP_DigestFinal_ex(mdctx, out, &md_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_destroy(mdctx);
#else
		EVP_MD_CTX_free(mdctx);
#endif
	}
	return md_len;
}

static void hexify(const char *data, char *hex)
{
	unsigned char hashdata[SHA_DIGEST_LENGTH];
	int mdlen, i;

	mdlen = sha_hash(data, strlen(data), hashdata);
	if (mdlen != SHA_DIGEST_LENGTH) {
		return;
	}

	// printf("mdlen=%d, string=%s\n\thash=", mdlen, data);
	for (i = 0, *hex = 0; i < sizeof(hashdata) / sizeof(hashdata[0]); i++) {
		sprintf(hex + (i*2), "%02X", hashdata[i]);
	}
	// printf("%s\n", hex);
}

/* access is desired read/write access
 * granted is what Mosquitto auth-plug actually granted
 */

void acl_cache(const char *clientid, const char *username, const char *topic, int access, int granted, void *userdata)
{
	char *data;
	char hex[SHA_DIGEST_LENGTH * 2 + 1];
	struct cacheentry *a, *tmp;
	struct userdata *ud = (struct userdata *)userdata;
	time_t cacheseconds = ud->acl_cacheseconds;
	time_t now;

	if (ud->acl_cacheseconds <= 0) {
		return;
	}

	if (ud->acl_cachejitter > 0) {
		cacheseconds += rand() * (ud->acl_cachejitter * 2) / RAND_MAX - ud->acl_cachejitter;
		if (cacheseconds <= 0) {
			return;
		}
	}

	if (!clientid || !username || !topic) {
		return;
	}

	now = time(NULL);

	data = malloc(strlen(clientid) + strlen(username) + strlen(topic) + 20);
	sprintf(data, "%s:%s:%s:%d", clientid, username, topic, access);
	hexify(data, hex);
	free(data);

	HASH_FIND_STR(ud->aclcache, hex, a);
	if (a) {
		a->granted = granted;

		if (time(NULL) > a->expire_time) {
			_log(LOG_DEBUG, " Expired [%s] for (%s,%s,%d)", hex, clientid, username, access);
			HASH_DEL(ud->aclcache, a);
			free(a);
		}
	} else {
		a = (struct cacheentry *)malloc(sizeof(struct cacheentry));
		strcpy(a->hex, hex);
		a->granted = granted;
		a->expire_time = now + cacheseconds;
		HASH_ADD_STR(ud->aclcache, hex, a);
		_log(LOG_DEBUG, " Cached  [%s] for (%s,%s,%d)", hex, clientid, username, access);
	}

	/*
	 * Check whole cache for items which need deleting. Important with
	 * clients who show up once only (mosquitto_[sp]ub with variable clientIDs
	 */

	HASH_ITER(hh, ud->aclcache, a, tmp) {
		if (now > a->expire_time) {
			_log(LOG_DEBUG, " Cleanup [%s]", a->hex);
			HASH_DEL(ud->aclcache, a);
			free(a);
		}
	}
}

int acl_cache_q(const char *clientid, const char *username, const char *topic, int access, void *userdata)
{
	char *data;
	char hex[SHA_DIGEST_LENGTH * 2 + 1];
	struct cacheentry *a;
	struct userdata *ud = (struct userdata *)userdata;
	int granted = MOSQ_ERR_UNKNOWN;

	if (ud->acl_cacheseconds <= 0) {
		return (MOSQ_ERR_UNKNOWN);
	}

	if (!clientid || !username || !topic) {
		return (MOSQ_ERR_UNKNOWN);
	}

	data = malloc(strlen(clientid) + strlen(username) + strlen(topic) + 20);
	sprintf(data, "%s:%s:%s:%d", clientid, username, topic, access);
	hexify(data, hex);
	free(data);

	HASH_FIND_STR(ud->aclcache, hex, a);
	if (a) {
		// printf("---> CACHED! %d\n", a->granted);

		if (time(NULL) > a->expire_time) {
			_log(LOG_DEBUG, " Expired [%s] for (%s,%s,%d)", hex, clientid, username, access);
			HASH_DEL(ud->aclcache, a);
			free(a);
		} else {
			granted = a->granted;
		}
	}

	return (granted);
}

/* granted is what Mosquitto auth-plug actually granted
 */

void auth_cache(const char *username, const char *password, int granted, void *userdata)
{
	char *data;
	char hex[SHA_DIGEST_LENGTH * 2 + 1];
	struct cacheentry *a, *tmp;
	struct userdata *ud = (struct userdata *)userdata;
	time_t cacheseconds = ud->auth_cacheseconds;
	time_t now;

	if (ud->auth_cacheseconds <= 0) {
		return;
	}

	if (ud->auth_cachejitter > 0) {
		cacheseconds += rand() * (ud->auth_cachejitter * 2) / RAND_MAX - ud->auth_cachejitter;
		if (cacheseconds <= 0) {
			return;
		}
	}

	if (!username || !password) {
		return;
	}

	now = time(NULL);

	data = malloc(strlen(username) + strlen(password) + 2);
	sprintf(data, "%s:%s", username, password);
	hexify(data, hex);
	free(data);

	HASH_FIND_STR(ud->authcache, hex, a);
	if (a) {
		a->granted = granted;

		if (time(NULL) > a->expire_time) {
			_log(LOG_DEBUG, " Expired [%s] for (%s)", hex, username);
			HASH_DEL(ud->authcache, a);
			free(a);
		}
	} else {
		a = (struct cacheentry *)malloc(sizeof(struct cacheentry));
		strcpy(a->hex, hex);
		a->granted = granted;
		a->expire_time = now + cacheseconds;

		HASH_ADD_STR(ud->authcache, hex, a);
		_log(LOG_DEBUG, " Cached  [%s] for (%s)", hex, username);
	}

	/*
	 * Check whole cache for items which need deleting. Important with
	 * clients who show up once only (mosquitto_[sp]ub with variable clientIDs
	 */

	HASH_ITER(hh, ud->authcache, a, tmp) {
		if (now > a->expire_time) {
			_log(LOG_DEBUG, " Cleanup [%s]", a->hex);
			HASH_DEL(ud->authcache, a);
			free(a);
		}
	}
}


int auth_cache_q(const char *username, const char *password, void *userdata)
{
	char *data;
	char hex[SHA_DIGEST_LENGTH * 2 + 1];
	struct cacheentry *a;
	struct userdata *ud = (struct userdata *)userdata;
	int granted = MOSQ_ERR_UNKNOWN;

	if (ud->auth_cacheseconds <= 0) {
		return (MOSQ_ERR_UNKNOWN);
	}

	if (!username || !password) {
		return (MOSQ_ERR_UNKNOWN);
	}

	data = malloc(strlen(username) + strlen(password) + 2);
	sprintf(data, "%s:%s", username, password);
	hexify(data, hex);
	free(data);

	HASH_FIND_STR(ud->authcache, hex, a);
	if (a) {
		if (time(NULL) > a->expire_time) {
			_log(LOG_DEBUG, " Expired [%s] for (%s)", hex, username);
			HASH_DEL(ud->authcache, a);
			free(a);
		} else {
			granted = a->granted;
		}
	}

	return granted;
}