#include <time.h>
#include "uthash.h"
#include <openssl/sha.h>

#ifndef __CACHE_H
# define __CACHE_H

struct cacheentry {
        char hex[SHA_DIGEST_LENGTH * 2 + 1];    /* key within struct */
        int granted;
        time_t expire_time;
        UT_hash_handle hh;
};

void acl_cache(const char *clientid, const char *username, const char *topic, int access, int granted, void *userdata);
int acl_cache_q(const char *clientid, const char *username, const char *topic, int access, void *userdata);

void auth_cache(const char *username, const char *password, int granted, void *userdata);
int auth_cache_q(const char *username, const char *password, void *userdata);

#endif