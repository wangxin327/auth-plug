#include <time.h>
#include "backends.h"
#include "cache.h"

#ifndef __USERDATA_H
# define _USERDATA_H

struct cliententry {
	void *key;
	char *username;
	char *clientid;
	UT_hash_handle hh;
};

struct userdata {
	struct backend_p **be_list;
	char *superusers;		/* Static glob list */
	int fallback_be;		/* Backend to use for anonymous connections */
	char *anonusername;		/* Configured name of anonymous MQTT user */
	time_t acl_cacheseconds;		/* number of seconds to cache ACL lookups */
	time_t acl_cachejitter;		/* number of seconds to add/remove to cache ACL lookups TTL */
	struct cacheentry *aclcache;
	time_t auth_cacheseconds;		/* number of seconds to cache AUTH lookups */
	time_t auth_cachejitter;		/* number of seconds to add/remove to cache AUTH lookups TTL */
	struct cacheentry *authcache;
	struct cliententry *clients;
};

#endif