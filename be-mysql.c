#ifdef BE_MYSQL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include "be-mysql.h"
#include "log.h"
#include "hash.h"
#include "backends.h"

struct mysql_backend {
	MYSQL *mysql;
	char *host;
	int port;	
	char *dbname;
	char *user;
	char *pass;
	bool auto_connect;
	char *userquery; //MUST return 1 row, 1 column
	char *aclquery; //MAY return n rows, 1 column, string
    char *ssl_key;
    char *ssl_cert;
    char *ssl_ca;
    char *ssl_capath;
    char *ssl_cipher;
};


static char *get_bool(char *option, char *defval)
{
	char *flag = p_stab(option);
	flag = flag ? flag : defval;
	if (!strcmp("true", flag) || !strcmp("false", flag)) {
		return flag;
	}
	_log(LOG_NOTICE, "WARN: %s is unexpected value -> %s", option, flag);
	return defval;
}

void *be_mysql_init()
{
	struct mysql_backend *conf;
	char *host, *user, *pass, *dbname, *p;  //数据库连接信息
	char *ssl_ca, *ssl_capath, *ssl_cert, *ssl_cipher, *ssl_key;  //证书信息
	char *userquery;
	char *opt_flag;
	int port;
	bool ssl_enabled;	
	my_bool reconnect = false;
	

	_log(LOG_DEBUG, "}}}} MYSQL");

	host = p_stab("host");
	p = p_stab("port");
	user = p_stab("user");
	pass = p_stab("pass");
	dbname = p_stab("dbname");
	
	opt_flag = get_bool("ssl_enabled", "false");
	if (!strcmp("true", opt_flag)) {
		ssl_enabled = true;
		_log(LOG_DEBUG, "SSL is enabled");
	}
	else{
		ssl_enabled = false;
		_log(LOG_DEBUG, "SSL is disabled");
	}
		
	host = (host) ? host : strdup("localhost");
	port = (!p) ? 3306 : atoi(p);

	userquery = p_stab("userquery");

	if (!userquery && !ssl_enabled) {
		_fatal("Mandatory option 'userquery' is missing and SSL is disabled.");
		return (NULL);
	}
	if ((conf = (struct mysql_backend *)malloc(sizeof(struct mysql_backend))) == NULL)
		return (NULL);

	conf->mysql = mysql_init(NULL);
	conf->host = host;
	conf->port = port;
	conf->user = user;
	conf->pass = pass;
	conf->auto_connect = false;
	conf->dbname = dbname;
	conf->userquery = userquery;
	conf->aclquery = p_stab("aclquery");

	if(ssl_enabled){
		// mysql_ssl_set(conf->mysql, ssl_key, ssl_cert, ssl_ca, ssl_capath, ssl_cipher);
        conf->ssl_key = p_stab("ssl_key");	
        conf->ssl_cert = p_stab("ssl_cert");
        conf->ssl_ca = p_stab("ssl_ca");
        conf->ssl_capath = p_stab("ssl_capath");
        conf->ssl_cipher = p_stab("ssl_cipher");
	}
	
	opt_flag = get_bool("mysql_auto_connect", "true");
	if (!strcmp("true", opt_flag)) {
		conf->auto_connect = true;
	}
	opt_flag = get_bool("mysql_opt_reconnect", "true");
	if (!strcmp("true", opt_flag)) {
		reconnect = true;
		mysql_options(conf->mysql, MYSQL_OPT_RECONNECT, &reconnect);
	}
	if (!mysql_real_connect(conf->mysql, host, user, pass, dbname, port, NULL, 0)) {
		_log(LOG_NOTICE, "%s", mysql_error(conf->mysql));
		if (!conf->auto_connect && !reconnect) {
			free(conf);
			mysql_close(conf->mysql);
			return (NULL);
		}
	}
	return ((void *)conf);
}

void be_mysql_destroy(void *handle)
{
	struct mysql_backend *conf = (struct mysql_backend *)handle;

	if (conf) {
		mysql_close(conf->mysql);
		if (conf->userquery)
			free(conf->userquery);
		if (conf->aclquery)
			free(conf->aclquery);
        if(conf->ssl_key)
            free(conf->ssl_key);
        if(conf->ssl_cert)
            free(conf->ssl_cert);
        if(conf->ssl_ca)
            free(conf->ssl_ca);
        if(conf->ssl_capath)
            free(conf->ssl_capath);
        if(conf->ssl_cipher)
            free(conf->ssl_cipher);
		free(conf);
	}
}

static char *escape(void *handle, const char *value, long *vlen)
{
	struct mysql_backend *conf = (struct mysql_backend *)handle;
	char *v;

	*vlen = strlen(value) * 2 + 1;
	if ((v = malloc(*vlen)) == NULL)
		return (NULL);
	mysql_real_escape_string(conf->mysql, v, value, strlen(value));
	return (v);
}

static bool auto_connect(struct mysql_backend *conf)
{
	if (conf->auto_connect) {
		if (!mysql_real_connect(conf->mysql, conf->host, conf->user, conf->pass, conf->dbname, conf->port, NULL, 0)) {
			fprintf(stderr, "do auto_connect but %s\n", mysql_error(conf->mysql));
			return false;
		}
		return true;
	}
	return false;
}

//select from sslinfo where 
int be_mysql_getsslinfo(void *)
{

}

int be_mysql_getuser(void *handle, const char *username, const char *password, char **phash, const char *clientid)
{
	struct mysql_backend *conf = (struct mysql_backend *)handle;
	char *query = NULL, *u = NULL, *value = NULL, *v;
	long nrows, ulen;
	MYSQL_RES *res = NULL;
	MYSQL_ROW rowdata;

	// fprintf(stderr, "------>%s<-----\n", clientid);
	if (!conf || !conf->userquery || !username || !*username)
		return BACKEND_DEFER;

	if (mysql_ping(conf->mysql)) {
		fprintf(stderr, "%s\n", mysql_error(conf->mysql));
		if (!auto_connect(conf)) {
			return BACKEND_ERROR;
		}
	}
	if ((u = escape(conf, username, &ulen)) == NULL)
		return BACKEND_ERROR;

	if ((query = malloc(strlen(conf->userquery) + ulen + 128)) == NULL) {
		free(u);
		return BACKEND_ERROR;
	}
	sprintf(query, conf->userquery, u, clientid);
	free(u);

	if (mysql_query(conf->mysql, query)) {
		fprintf(stderr, "%s\n", mysql_error(conf->mysql));
		goto out;
	}
	res = mysql_store_result(conf->mysql);
	if ((nrows = mysql_num_rows(res)) != 1) {
		//DEBUG fprintf(stderr, "rowcount = %ld; not ok\n", nrows);
		goto out;
	}
	if (mysql_num_fields(res) != 1) {
		//DEBUG fprintf(stderr, "numfields not ok\n");
		goto out;
	}
	if ((rowdata = mysql_fetch_row(res)) == NULL) {
		goto out;
	}
	v = rowdata[0];
	value = (v) ? strdup(v) : NULL;


out:

	mysql_free_result(res);
	free(query);

	*phash = value;
	return BACKEND_DEFER;
}

/*
 * Check ACL. username is the name of the connected user attempting to access
 * topic is the topic user is trying to access (may contain wildcards) acc is
 * desired type of access: read/write for subscriptions (READ) (1) for
 * publish (WRITE) (2)
 * 
 * SELECT topic FROM table WHERE username = '%s' AND (acc & %d)		//
 * may user SUB or PUB topic? SELECT topic FROM table WHERE username = '%s'
 * / ignore ACC
 */

int be_mysql_aclcheck(void *handle, const char *clientid, const char *username, const char *topic, int acc)
{
	struct mysql_backend *conf = (struct mysql_backend *)handle;
	char *query = NULL, *u = NULL, *v;
	long ulen;
	int match = BACKEND_DEFER;
	bool bf;
	MYSQL_RES *res = NULL;
	MYSQL_ROW rowdata;

	if (!conf || !conf->aclquery)
		return BACKEND_DEFER;

	if (mysql_ping(conf->mysql)) {
		fprintf(stderr, "%s\n", mysql_error(conf->mysql));
		if (!auto_connect(conf)) {
			return (BACKEND_ERROR);
		}
	}
	if ((u = escape(conf, username, &ulen)) == NULL)
		return (BACKEND_ERROR);

	if ((query = malloc(strlen(conf->aclquery) + ulen + 128)) == NULL) {
		free(u);
		return (BACKEND_ERROR);
	}
	sprintf(query, conf->aclquery, u, acc);
	free(u);

	//_log(LOG_DEBUG, "SQL: %s", query);

	if (mysql_query(conf->mysql, query)) {
		_log(LOG_NOTICE, "%s", mysql_error(conf->mysql));
		match = BACKEND_ERROR;
		goto out;
	}
	res = mysql_store_result(conf->mysql);
	if (mysql_num_fields(res) != 1) {
		fprintf(stderr, "numfields not ok\n");
		goto out;
	}
	while (match == 0 && (rowdata = mysql_fetch_row(res)) != NULL) {
		if ((v = rowdata[0]) != NULL) {

			/*
			 * Check mosquitto_match_topic. If true, if true, set
			 * match and break out of loop.
			 */

			char *expanded;

			t_expand(clientid, username, v, &expanded);
			if (expanded && *expanded) {
				mosquitto_topic_matches_sub(expanded, topic, &bf);
				if (bf) match = BACKEND_ALLOW;
				_log(LOG_DEBUG, "  mysql: topic_matches(%s, %s) == %d",
				     expanded, v, bf);

				free(expanded);
			}
		}
	}

out:

	mysql_free_result(res);
	free(query);

	return (match);
}
#endif  /* BE_MYSQL */
