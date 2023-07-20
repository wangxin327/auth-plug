#ifndef TRUE
# define TRUE (1)
#endif
#ifndef FALSE
# define FALSE (0)
#endif
#ifndef BACKEND_DEFER
# define BACKEND_DEFER (0)
#endif
#ifndef BACKEND_ALLOW
# define BACKEND_ALLOW (1)
#endif
#ifndef BACKEND_ERROR
# define BACKEND_ERROR (2)
#endif
#ifndef BACKEND_DENY
# define BACKEND_DENY (3)
#endif

#ifndef __BACKENDS_H
# define __BACKENDS_H

typedef void (f_kill)(void *conf);
typedef int (f_getuser)(void *conf, const char *username, const char *password, char **phash, const char *clientid);
typedef int (f_superuser)(void *conf, const char *username);
typedef int (f_aclcheck)(void *conf, const char *clientid, const char *username, const char *topic, int acc);

void t_expand(const char *clientid, const char *username, const char *in, char **res);

#endif