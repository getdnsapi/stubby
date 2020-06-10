#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdint.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

typedef void(*stubby_verror_t)(getdns_loglevel_type level, const char *fmt, va_list ap);
typedef void(*stubby_vlog_t)(void *userarg, uint64_t system,
                             getdns_loglevel_type level,
                             const char *fmt, va_list ap);

void stubby_set_verror(stubby_verror_t err);
void stubby_set_vlog(stubby_vlog_t log);

void stubby_log(void *userarg, uint64_t system,
                getdns_loglevel_type level, const char *fmt, ...);

void stubby_error(const char *fmt, ...);
void stubby_warning(const char *fmt, ...);

void stubby_set_getdns_logging(getdns_context *context, int loglevel);

#endif
