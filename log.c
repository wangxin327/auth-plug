#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include "log.h"

int log_quiet=0;

void (*_log)(int priority, const char *fmt, ...);

void log_init(void)
{
#if MOSQ_AUTH_PLUGIN_VERSION >= 3
	_log = __log;
#elif (LIBMOSQUITTO_MAJOR > 1) || ((LIBMOSQUITTO_MAJOR == 1) && (LIBMOSQUITTO_MINOR >= 4))
	_log = mosquitto_log_printf;
#else
	_log = __log;
#endif
}

void __log(int priority, const char *fmt, ...)
{
	va_list va;
	time_t now;

	if (log_quiet && priority <= LOG_DEBUG)
		return;

	time(&now);

	va_start(va, fmt);
	fprintf(stderr, "%ld: |-- ", now);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	fflush(stderr);
	va_end(va);
}

void _fatal(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fprintf(stderr, "|-- ");
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	fprintf(stderr, "|-- *** ABORT.\n");
	fflush(stderr);
	va_end(va);
	exit(1);
}