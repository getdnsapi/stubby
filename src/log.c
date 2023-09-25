/*
 * Copyright (c) 2020, NLNet Labs, Sinodun
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the names of the copyright holders nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdarg.h>
#include <stdio.h>

#if defined(STUBBY_ON_WINDOWS)
#include <sys/types.h>
#include <sys/timeb.h>
#endif

#if defined(HAVE_VSYSLOG)
#include <syslog.h>
#endif

#include "log.h"

stubby_log_target_t log_target = STUBBY_LOG_STDERR;

#if defined(HAVE_VSYSLOG)
static void stubby_syslog_open()
{
	static int is_syslog_open = 0;

	if (!is_syslog_open) {
		openlog("stubby", LOG_PID, LOG_DAEMON);
		is_syslog_open = 1;
	}
}

static int stubby_syslog_priority(getdns_loglevel_type level)
{
	int priority = LOG_INFO;

	switch (level) {
		case GETDNS_LOG_EMERG:
			priority = LOG_EMERG;
			break;
		case GETDNS_LOG_ALERT:
			priority = LOG_ALERT;
			break;
		case GETDNS_LOG_CRIT:
			priority = LOG_CRIT;
			break;
		case GETDNS_LOG_ERR:
			priority = LOG_ERR;
			break;
		case GETDNS_LOG_WARNING:
			priority = LOG_WARNING;
			break;
		case GETDNS_LOG_NOTICE:
			priority = LOG_NOTICE;
			break;
		case GETDNS_LOG_INFO:
			priority = LOG_INFO;
			break;
		case GETDNS_LOG_DEBUG:
			priority = LOG_DEBUG;
			break;
	}

	return priority;
}
#endif

static void default_stubby_verror(getdns_loglevel_type level, const char *fmt, va_list ap)
{
	switch (log_target) {
#if defined(HAVE_VSYSLOG)
		case STUBBY_LOG_SYSLOG:
			stubby_syslog_open();
			vsyslog(stubby_syslog_priority(level), fmt, ap);
			break;
#endif
		case STUBBY_LOG_STDERR:
			(void) level;
			(void) vfprintf(stderr, fmt, ap);
			break;
	}
}

long log_level = GETDNS_LOG_DEBUG + 1;

static void default_stubby_vlog(void *userarg, uint64_t system,
                                getdns_loglevel_type level,
                                const char *fmt, va_list ap)
{
	(void)userarg; (void)system;

	switch (log_target) {
#if defined(HAVE_VSYSLOG)
		case STUBBY_LOG_SYSLOG:
			stubby_syslog_open();
			vsyslog(stubby_syslog_priority(level), fmt, ap);
			break;
#endif
		case STUBBY_LOG_STDERR:
			(void)0;
			struct timeval tv;
			struct tm tm;
			char buf[10];
#if defined(STUBBY_ON_WINDOWS)
			struct _timeb timeb;
			time_t tsec;
			if (level > log_level) return;

			_ftime_s(&timeb);
			tsec = (time_t)timeb.time;
			tv.tv_usec = timeb.millitm * 1000;
			gmtime_s(&tm, &tsec);
#else
			if (level > log_level) return;
			gettimeofday(&tv, NULL);
			gmtime_r(&tv.tv_sec, &tm);
#endif
			strftime(buf, 10, "%H:%M:%S", &tm);
			(void)level;
			(void) fprintf(stderr, "[%s.%.6d] STUBBY: ", buf, (int)tv.tv_usec);
			(void) vfprintf(stderr, fmt, ap);
			break;
	}
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

void stubby_debug(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        stubby_verror(GETDNS_LOG_DEBUG, fmt, args);
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

void stubby_set_log_funcs(stubby_verror_t errfunc, stubby_vlog_t logfunc)
{
        stubby_verror = errfunc;
        stubby_vlog = logfunc;
}

void stubby_set_log_target(stubby_log_target_t target)
{
	log_target = target;
}

void stubby_set_getdns_logging(getdns_context *context, int loglevel)
{
        (void) getdns_context_set_logfunc(context, NULL, GETDNS_LOG_UPSTREAM_STATS, loglevel, stubby_vlog);
}
