#include "config.h"

#include <stdio.h>

#include "log.h"

static void default_stubby_verror(getdns_loglevel_type level, const char *fmt, va_list ap)
{
        (void) level;
        (void) vfprintf(stderr, fmt, ap);
        (void) fputc('\n', stderr);
}

static void default_stubby_vlog(void *userarg, uint64_t system,
                                getdns_loglevel_type level,
                                const char *fmt, va_list ap)
{
        struct timeval tv;
        struct tm tm;
        char buf[10];
#if defined(STUBBY_ON_WINDOWS)
        time_t tsec;

        gettimeofday(&tv, NULL);
        tsec = (time_t) tv.tv_sec;
        gmtime_s(&tm, (const time_t *) &tsec);
#else
        gettimeofday(&tv, NULL);
        gmtime_r(&tv.tv_sec, &tm);
#endif
        strftime(buf, 10, "%H:%M:%S", &tm);
        (void)userarg; (void)system; (void)level;
        (void) fprintf(stderr, "[%s.%.6d] STUBBY: ", buf, (int)tv.tv_usec);
        (void) vfprintf(stderr, fmt, ap);
        (void) fputc('\n', stderr);
}

static stubby_verror_t stubby_verror = default_stubby_verror;
static stubby_vlog_t stubby_vlog = default_stubby_vlog;

void stubby_error(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        stubby_verror(GETDNS_LOG_ERR, fmt, args);
        va_end(args);
}

void stubby_warning(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        stubby_verror(GETDNS_LOG_WARNING, fmt, args);
        va_end(args);
}

void stubby_log(void *userarg, uint64_t system,
                getdns_loglevel_type level, const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        stubby_vlog(userarg, system, level, fmt, args);
        va_end(args);
}

void stubby_set_getdns_logging(getdns_context *context, int loglevel)
{
        (void) getdns_context_set_logfunc(context, NULL, GETDNS_LOG_UPSTREAM_STATS, loglevel, stubby_vlog);
}
