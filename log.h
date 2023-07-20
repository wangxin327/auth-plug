#include <mosquitto.h>
#if (LIBMOSQUITTO_MAJOR > 1) || ((LIBMOSQUITTO_MAJOR == 1) && (LIBMOSQUITTO_MINOR >= 4))
#define LOG_DEBUG (MOSQ_LOG_DEBUG)
#define LOG_NOTICE (MOSQ_LOG_NOTICE)
#else
#define LOG_DEBUG (1)
#define LOG_NOTICE (2)
#endif

extern void (*_log)(int priority, const char *fmt, ...);

void log_init(void);
void __log(int priority, const char *fmt, ...);
void _fatal(const char *fmt, ...);

extern int log_quiet;