#ifdef BE_MYSQL

#include <mysql.h>

void *be_mysql_init();
void be_mysql_destroy(void *conf);
int be_mysql_getuser(void *conf, const char *username, const char *password, char **phash, const char *clientid);
int be_mysql_superuser(void *conf, const char *username);
int be_mysql_aclcheck(void *conf, const char *clientid, const char *username, const char *topic, int acc);
#endif /* BE_MYSQL */
