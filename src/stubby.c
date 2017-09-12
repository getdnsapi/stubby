/*
 * Copyright (c) 2013, NLNet Labs, Verisign, Inc.
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
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#ifndef STUBBY_ON_WINDOWS
#include <unistd.h>
#endif
#include <signal.h>

#define STUBBYPIDFILE RUNSTATEDIR"/stubby.pid"

#ifdef STUBBY_ON_WINDOWS
#define DEBUG_ON(...) do { \
	                struct timeval tv; \
	                struct tm tm; \
	                char buf[10]; \
	                time_t tsec; \
	                \
	                gettimeofday(&tv, NULL); \
	                tsec = (time_t) tv.tv_sec; \
	                gmtime_s(&tm, (const time_t *) &tsec); \
	                strftime(buf, 10, "%H:%M:%S", &tm); \
	                fprintf(stderr, "[%s.%.6d] ", buf, (int)tv.tv_usec); \
	                fprintf(stderr, __VA_ARGS__); \
	        } while (0)
#else
#define DEBUG_ON(...) do { \
	                struct timeval tv; \
	                struct tm tm; \
	                char buf[10]; \
	                \
	                gettimeofday(&tv, NULL); \
	                gmtime_r(&tv.tv_sec, &tm); \
	                strftime(buf, 10, "%H:%M:%S", &tm); \
	                fprintf(stderr, "[%s.%.6d] ", buf, (int)tv.tv_usec); \
	                fprintf(stderr, __VA_ARGS__); \
	        } while (0)
#endif
#define DEBUG_OFF(...) do {} while (0)

#if defined(SERVER_DEBUG) && SERVER_DEBUG
#include <time.h>
#define DEBUG_SERVER(...) DEBUG_ON(__VA_ARGS__)
#else
#define DEBUG_SERVER(...) DEBUG_OFF(__VA_ARGS__)
#endif

static const char *default_config =
"{ resolution_type: GETDNS_RESOLUTION_STUB"
", dns_transport_list: [ GETDNS_TRANSPORT_TLS"
"                      , GETDNS_TRANSPORT_UDP"
"                      , GETDNS_TRANSPORT_TCP ]"
", idle_timeout: 10000"
", listen_addresses: [ 127.0.0.1@53, 0::1@53 ]"
", tls_query_padding_blocksize: 256"
", edns_client_subnet_private : 1"
", round_robin_upstreams: 1"
"}";

static getdns_context  *context = NULL;
static getdns_dict *listen_dict = NULL;
static getdns_list *listen_list = NULL;
static size_t listen_count = 0;
static int run_in_foreground = 1;

static void stubby_local_log(void *userarg, uint64_t system,
	getdns_loglevel_type level, const char *fmt, ...);


void
print_usage(FILE *out, const char *progname)
{
	fprintf(out, "usage: %s [<option> ...] \\\n", progname);
	fprintf(out, "\t-C\t<filename>\n");
	fprintf(out, "\t\tRead settings from config file <filename>\n");
	fprintf(out, "\t\tThe getdns context will be configured with these settings\n");
	fprintf(out, "\t\tThe file must be in json dict format.\n");
	fprintf(out, "\t\tBy default, the configuration file location is obtained\n");
	fprintf(out, "\t\tby looking for files in the following order:\n");
	fprintf(out, "\t\t\t\"/etc/stubby.conf\"\n");
	fprintf(out, "\t\t\t\"%s/.stubby.conf\"\n", getenv("HOME"));
	fprintf(out, "\t\t\t\"%s/stubby.conf\"\n", STUBBYCONFDIR);
	fprintf(out, "\t\tAn default file (Using Strict mode) is installed as\n");
	fprintf(out, "\t\t\t\"%s/stubby.conf\"\n", STUBBYCONFDIR);
#ifndef STUBBY_ON_WINDOWS
	fprintf(out, "\t-g\tRun stubby in background (default is foreground)\n");
#endif
	fprintf(out, "\t-h\tPrint this help\n");
	fprintf(out, "\t-i\tValidate and print the configuration only. Useful to validate config file contents.\n");
	fprintf(out, "\t-l\tEnable logging of all logs (same as -v 7)\n");
	fprintf(out, "\t-v\tSpecify logging level (overrides -l option). Values are\n");
	fprintf(out, "\t\t\t0: EMERG  - %s\n", GETDNS_LOG_EMERG_TEXT);
	fprintf(out, "\t\t\t1: ALERT  - %s\n", GETDNS_LOG_ALERT_TEXT);
	fprintf(out, "\t\t\t2: CRIT   - %s\n", GETDNS_LOG_CRIT_TEXT);
	fprintf(out, "\t\t\t3: ERROR  - %s\n", GETDNS_LOG_ERR_TEXT);
	fprintf(out, "\t\t\t4: WARN   - %s\n", GETDNS_LOG_WARNING_TEXT);
	fprintf(out, "\t\t\t5: NOTICE - %s\n", GETDNS_LOG_NOTICE_TEXT);
	fprintf(out, "\t\t\t6: INFO   - %s\n", GETDNS_LOG_INFO_TEXT);
	fprintf(out, "\t\t\t7: DEBUG  - %s\n", GETDNS_LOG_DEBUG_TEXT);
}

#define GETDNS_RETURN_IO_ERROR ((getdns_return_t) 3000)

static const char *_getdns_strerror(getdns_return_t r)
{
	return r == GETDNS_RETURN_IO_ERROR ? strerror(errno)
	                                   : getdns_get_errorstr_by_id(r);
}

static getdns_return_t parse_config(const char *config_str)
{
	getdns_dict *config_dict;
	getdns_list *list;
	getdns_return_t r;

	if ((r = getdns_str2dict(config_str, &config_dict))) {
		fprintf(stderr, "Could not parse config file %s, \"%s\"\n",
		    config_str, _getdns_strerror(r));
		return r;

	}
	if (!(r = getdns_dict_get_list(
	    config_dict, "listen_addresses", &list))) {
		if (listen_list && !listen_dict) {
			getdns_list_destroy(listen_list);
			listen_list = NULL;
		}
		/* Strange construction to copy the list.
		 * Needs to be done, because config dict
		 * will get destroyed.
		 */
		if (!listen_dict &&
		    !(listen_dict = getdns_dict_create())) {
			fprintf(stderr, "Could not create "
					"listen_dict");
			r = GETDNS_RETURN_MEMORY_ERROR;

		} else if ((r = getdns_dict_set_list(
		    listen_dict, "listen_list", list)))
			fprintf(stderr, "Could not set listen_list");

		else if ((r = getdns_dict_get_list(
		    listen_dict, "listen_list", &listen_list)))
			fprintf(stderr, "Could not get listen_list");

		else if ((r = getdns_list_get_length(
		    listen_list, &listen_count)))
			fprintf(stderr, "Could not get listen_count");

		(void) getdns_dict_remove_name(
		    config_dict, "listen_addresses");
	}
	if (!r && (r = getdns_context_config(context, config_dict))) {
		fprintf(stderr, "Could not configure context with "
		    "config dict: %s\n", _getdns_strerror(r));
	}
	getdns_dict_destroy(config_dict);
	return r;
}

static getdns_return_t parse_config_file(const char *fn)
{
	FILE *fh;
	char *config_file = NULL;
	long config_file_sz;
	getdns_return_t r;

	if (!(fh = fopen(fn, "r")))
		return GETDNS_RETURN_IO_ERROR;

	if (fseek(fh, 0,SEEK_END) == -1) {
		perror("fseek");
		fclose(fh);
		return GETDNS_RETURN_IO_ERROR;
	}
	config_file_sz = ftell(fh);
	if (config_file_sz <= 0) {
		/* Empty config is no config */
		fclose(fh);
		return GETDNS_RETURN_IO_ERROR;
	}
	if (!(config_file = malloc(config_file_sz + 1))){
		fclose(fh);
		fprintf(stderr, "Could not allocate memory for \"%s\"\n", fn);
		return GETDNS_RETURN_MEMORY_ERROR;
	}
	rewind(fh);
	if (fread(config_file, 1, config_file_sz, fh) != (size_t)config_file_sz) {
		fprintf( stderr, "An error occurred while reading \"%s\": %s\n"
		       , fn, strerror(errno));
		fclose(fh);
		free(config_file);
		return GETDNS_RETURN_IO_ERROR;
	}
	config_file[config_file_sz] = 0;
	fclose(fh);
	r = parse_config(config_file);
	free(config_file);
	if (r == GETDNS_RETURN_GOOD)
		stubby_local_log(NULL,GETDNS_LOG_UPSTREAM_STATS, GETDNS_LOG_DEBUG,
			       "Read config from file %s\n", fn);
	return r;
}

typedef struct dns_msg {
	getdns_transaction_t  request_id;
	getdns_dict          *request;
	uint32_t              rt;
	uint32_t              ad_bit;
	uint32_t              do_bit;
	uint32_t              cd_bit;
	int                   has_edns0;
} dns_msg;

#if defined(SERVER_DEBUG) && SERVER_DEBUG
#define SERVFAIL(error,r,msg,resp_p) do { \
	if (r)	DEBUG_SERVER("%s: %s\n", error, _getdns_strerror(r)); \
	else	DEBUG_SERVER("%s\n", error); \
	servfail(msg, resp_p); \
	} while (0)
#else
#define SERVFAIL(error,r,msg,resp_p) servfail(msg, resp_p)
#endif

void servfail(dns_msg *msg, getdns_dict **resp_p)
{
	getdns_dict *dict;

	if (*resp_p)
		getdns_dict_destroy(*resp_p);
	if (!(*resp_p = getdns_dict_create()))
		return;
	if (msg) {
		if (!getdns_dict_get_dict(msg->request, "header", &dict))
			getdns_dict_set_dict(*resp_p, "header", dict);
		if (!getdns_dict_get_dict(msg->request, "question", &dict))
			getdns_dict_set_dict(*resp_p, "question", dict);
		(void) getdns_dict_set_int(*resp_p, "/header/ra",
		    msg->rt == GETDNS_RESOLUTION_RECURSING ? 1 : 0);
	}
	(void) getdns_dict_set_int(
	    *resp_p, "/header/rcode", GETDNS_RCODE_SERVFAIL);
	(void) getdns_dict_set_int(*resp_p, "/header/qr", 1);
	(void) getdns_dict_set_int(*resp_p, "/header/ad", 0);
}

static getdns_return_t _handle_edns0(
    getdns_dict *response, int has_edns0)
{
	getdns_return_t r;
	getdns_list *additional;
	size_t len, i;
	getdns_dict *rr;
	uint32_t rr_type;
	char remove_str[100] = "/replies_tree/0/additional/";

	if ((r = getdns_dict_set_int(
	    response, "/replies_tree/0/header/do", 0)))
		return r;
	if ((r = getdns_dict_get_list(response, "/replies_tree/0/additional",
	    &additional)))
		return r;
	if ((r = getdns_list_get_length(additional, &len)))
		return r;
	for (i = 0; i < len; i++) {
		if ((r = getdns_list_get_dict(additional, i, &rr)))
			return r;
		if ((r = getdns_dict_get_int(rr, "type", &rr_type)))
			return r;
		if (rr_type != GETDNS_RRTYPE_OPT)
			continue;
		if (has_edns0) {
			(void) getdns_dict_set_int(rr, "do", 0);
			break;
		}
		(void) snprintf(remove_str + 27, 60, "%d", (int)i);
		if ((r = getdns_dict_remove_name(response, remove_str)))
			return r;
		break;
	}
	return GETDNS_RETURN_GOOD;
}

static void request_cb(
    getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t transaction_id)
{
	dns_msg *msg = (dns_msg *)userarg;
	uint32_t qid;
	getdns_return_t r = GETDNS_RETURN_GOOD;
	uint32_t n, rcode, dnssec_status;

#if defined(SERVER_DEBUG) && SERVER_DEBUG
	getdns_bindata *qname;
	char *qname_str, *unknown_qname = "<unknown_qname>";

	if (getdns_dict_get_bindata(msg->request, "/question/qname", &qname)
	||  getdns_convert_dns_name_to_fqdn(qname, &qname_str))
		qname_str = unknown_qname;

	DEBUG_SERVER("reply for: %p %"PRIu64" %d (edns0: %d, do: %d, ad: %d,"
	    " cd: %d, qname: %s)\n", (void *)msg, transaction_id, (int)callback_type,
	    msg->has_edns0, msg->do_bit, msg->ad_bit, msg->cd_bit, qname_str);

	if (qname_str != unknown_qname)
		free(qname_str);
#else
	(void)transaction_id;
#endif
	assert(msg);

	if (callback_type != GETDNS_CALLBACK_COMPLETE)
		SERVFAIL("Callback type not complete",
		    callback_type, msg, &response);

	else if (!response)
		SERVFAIL("Missing response", 0, msg, &response);

	else if ((r = getdns_dict_get_int(msg->request, "/header/id", &qid)) ||
	    (r=getdns_dict_set_int(response,"/replies_tree/0/header/id",qid)))
		SERVFAIL("Could not copy QID", r, msg, &response);

	else if (getdns_dict_get_int(
	    response, "/replies_tree/0/header/rcode", &rcode))
		SERVFAIL("No reply in replies tree", 0, msg, &response);

	/* ansers when CD or not BOGUS */
	else if (!msg->cd_bit && !getdns_dict_get_int(
	    response, "/replies_tree/0/dnssec_status", &dnssec_status)
	    && dnssec_status == GETDNS_DNSSEC_BOGUS)
		SERVFAIL("DNSSEC status was bogus", 0, msg, &response);

	else if (rcode == GETDNS_RCODE_SERVFAIL)
		servfail(msg, &response);

	/* RRsigs when DO and (CD or not BOGUS) 
	 * Implemented in conversion to wireformat function by checking for DO
	 * bit.  In recursing resolution mode we have to copy the do bit from
	 * the request, because libunbound has it in the answer always.
	 */
	else if (msg->rt == GETDNS_RESOLUTION_RECURSING && !msg->do_bit &&
	    (r = _handle_edns0(response, msg->has_edns0)))
		SERVFAIL("Could not handle EDNS0", r, msg, &response);

	/* AD when (DO or AD) and SECURE */
	else if ((r = getdns_dict_set_int(response,"/replies_tree/0/header/ad",
	    ((msg->do_bit || msg->ad_bit)
	    && (  (!msg->cd_bit && dnssec_status == GETDNS_DNSSEC_SECURE)
	       || ( msg->cd_bit && !getdns_dict_get_int(response,
	            "/replies_tree/0/dnssec_status", &dnssec_status)
	          && dnssec_status == GETDNS_DNSSEC_SECURE ))) ? 1 : 0)))
		SERVFAIL("Could not set AD bit", r, msg, &response);

	else if (msg->rt == GETDNS_RESOLUTION_STUB)
		; /* following checks are for RESOLUTION_RECURSING only */
	
	else if ((r =  getdns_dict_set_int(
	    response, "/replies_tree/0/header/cd", msg->cd_bit)))
		SERVFAIL("Could not copy CD bit", r, msg, &response);

	else if ((r = getdns_dict_get_int(
	    response, "/replies_tree/0/header/ra", &n)))
		SERVFAIL("Could not get RA bit from reply", r, msg, &response);

	else if (n == 0)
		SERVFAIL("Recursion not available", 0, msg, &response);

	if ((r = getdns_reply(context, response, msg->request_id))) {
		fprintf(stderr, "Could not reply: %s\n", _getdns_strerror(r));
		/* Cancel reply */
		(void) getdns_reply(context, NULL, msg->request_id);
	}
	if (msg) {
		getdns_dict_destroy(msg->request);
		free(msg);
	}
	if (response)
		getdns_dict_destroy(response);
}	

static void incoming_request_handler(getdns_context *context,
    getdns_callback_type_t callback_type, getdns_dict *request,
    void *userarg, getdns_transaction_t request_id)
{
	getdns_bindata *qname;
	char *qname_str = NULL;
	uint32_t qtype;
	uint32_t qclass;
	getdns_return_t r;
	getdns_dict *header;
	uint32_t n;
	getdns_list *list;
	getdns_transaction_t transaction_id = 0;
	getdns_dict *qext = NULL;
	dns_msg *msg = NULL;
	getdns_dict *response = NULL;
	size_t i, len;
	getdns_list *additional;
	getdns_dict *rr;
	uint32_t rr_type;

	(void)callback_type;
	(void)userarg;

	if (!(qext = getdns_dict_create_with_context(context)) ||
	    !(msg = malloc(sizeof(dns_msg))))
		goto error;

	/* pass through the header and the OPT record */
	n = 0;
	msg->request_id = request_id;
	msg->request = request;
	msg->ad_bit = msg->do_bit = msg->cd_bit = 0;
	msg->has_edns0 = 0;
	msg->rt = GETDNS_RESOLUTION_RECURSING;
	(void) getdns_dict_get_int(request, "/header/ad", &msg->ad_bit);
	(void) getdns_dict_get_int(request, "/header/cd", &msg->cd_bit);
	if (!getdns_dict_get_list(request, "additional", &additional)) {
		if (getdns_list_get_length(additional, &len))
			len = 0;
		for (i = 0; i < len; i++) {
			if (getdns_list_get_dict(additional, i, &rr))
				break;
			if (getdns_dict_get_int(rr, "type", &rr_type))
				break;
			if (rr_type != GETDNS_RRTYPE_OPT)
				continue;
			msg->has_edns0 = 1;
			(void) getdns_dict_get_int(rr, "do", &msg->do_bit);
			break;
		}
	}
	if ((r = getdns_context_get_resolution_type(context, &msg->rt)))
		fprintf(stderr, "Could get resolution type from context: %s\n",
		    _getdns_strerror(r));

	if (msg->rt == GETDNS_RESOLUTION_STUB) {
		(void)getdns_dict_set_int(
		    qext , "/add_opt_parameters/do_bit", msg->do_bit);
		if (!getdns_dict_get_dict(request, "header", &header))
			(void)getdns_dict_set_dict(qext, "header", header);

	}
	if (msg->cd_bit)
		getdns_dict_set_int(qext, "dnssec_return_all_statuses",
		    GETDNS_EXTENSION_TRUE);

	if (!getdns_dict_get_int(request, "/additional/0/extended_rcode",&n))
		(void)getdns_dict_set_int(
		    qext, "/add_opt_parameters/extended_rcode", n);

	if (!getdns_dict_get_int(request, "/additional/0/version", &n))
		(void)getdns_dict_set_int(
		    qext, "/add_opt_parameters/version", n);

	if (!getdns_dict_get_int(
	    request, "/additional/0/udp_payload_size", &n))
		(void)getdns_dict_set_int(qext,
		    "/add_opt_parameters/maximum_udp_payload_size", n);

	if (!getdns_dict_get_list(
	    request, "/additional/0/rdata/options", &list))
		(void)getdns_dict_set_list(qext,
		    "/add_opt_parameters/options", list);

	if ((r = getdns_dict_get_bindata(request,"/question/qname",&qname)))
		fprintf(stderr, "Could not get qname from query: %s\n",
		    _getdns_strerror(r));

	else if ((r = getdns_convert_dns_name_to_fqdn(qname, &qname_str)))
		fprintf(stderr, "Could not convert qname: %s\n",
		    _getdns_strerror(r));

	else if ((r=getdns_dict_get_int(request,"/question/qtype",&qtype)))
		fprintf(stderr, "Could get qtype from query: %s\n",
		    _getdns_strerror(r));

	else if ((r=getdns_dict_get_int(request,"/question/qclass",&qclass)))
		fprintf(stderr, "Could get qclass from query: %s\n",
		    _getdns_strerror(r));

	else if ((r = getdns_dict_set_int(qext, "specify_class", qclass)))
		fprintf(stderr, "Could set class from query: %s\n",
		    _getdns_strerror(r));

	else if ((r = getdns_general(context, qname_str, qtype,
	    qext, msg, &transaction_id, request_cb)))
		fprintf(stderr, "Could not schedule query: %s\n",
		    _getdns_strerror(r));
	else {
		DEBUG_SERVER("scheduled: %p %"PRIu64" for %s %d\n",
		    (void *)msg, transaction_id, qname_str, (int)qtype);
		getdns_dict_destroy(qext);
		free(qname_str);
		return;
	}
error:
	if (qname_str)
		free(qname_str);
	if (qext)
		getdns_dict_destroy(qext);
	servfail(msg, &response);
#if defined(SERVER_DEBUG) && SERVER_DEBUG
	do {
		char *request_str = getdns_pretty_print_dict(request);
		char *response_str = getdns_pretty_print_dict(response);
		DEBUG_SERVER("request error, request: %s\n, response: %s\n"
		            , request_str, response_str);
		free(response_str);
		free(request_str);
	} while(0);
#endif
	if ((r = getdns_reply(context, response, request_id))) {
		fprintf(stderr, "Could not reply: %s\n",
		    _getdns_strerror(r));
		/* Cancel reply */
		getdns_reply(context, NULL, request_id);
	}
	if (msg) {
		if (msg->request)
			getdns_dict_destroy(msg->request);
		free(msg);
	}
	if (response)
		getdns_dict_destroy(response);
}

static void stubby_log(void *userarg, uint64_t system,
    getdns_loglevel_type level, const char *fmt, va_list ap)
{
	struct timeval tv;
	struct tm tm;
	char buf[10];
#ifdef GETDNS_ON_WINDOWS
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
}

void stubby_local_log(void *userarg, uint64_t system,
    getdns_loglevel_type level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	stubby_log(userarg, system, level, fmt, args);
	va_end(args);
}

int
main(int argc, char **argv)
{
	char home_stubby_conf_fn_spc[1024], *home_stubby_conf_fn = NULL;
	const char *custom_config_fn = NULL;
	int fn_sz;
	int print_api_info = 0;
	int log_connections = 0;
	getdns_return_t r;
	int opt;
	long log_level = 7; 
	char *ep;

#ifndef USE_WINSOCK
	char *prg_name = strrchr(argv[0], '/');
#else
	char *prg_name = strrchr(argv[0], '\\');
#endif
	prg_name = prg_name ? prg_name + 1 : argv[0];

	while ((opt = getopt(argc, argv, "C:ighlv:")) != -1) {
		switch (opt) {
		case 'C':
			custom_config_fn = optarg;
			break;
		case 'g':
			run_in_foreground = 0;
			break;
		case 'h':
			print_usage(stdout, prg_name);
			exit(EXIT_SUCCESS);
		case 'i':
			print_api_info = 1;
			break;
		case 'l':
			log_connections = 1;
			break;
		case 'v':
			log_connections = 1;
			errno = 0;
			log_level = strtol(optarg, &ep, 10);
			if (log_level < 0 ||  log_level > 7 || *ep != '\0' || 
			    (errno == ERANGE &&
			    (log_level == LONG_MAX || log_level == LONG_MIN)) ) {
				fprintf(stderr, "Log level '%s' is invalid or out of range (0-7)\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			print_usage(stderr, prg_name);
			exit(EXIT_FAILURE);
		}
	}

	if ((r = getdns_context_create(&context, 1))) {
		fprintf(stderr, "Create context failed: %s\n",
		        _getdns_strerror(r));
		return r;
	}
	if (log_connections) {
		(void) getdns_context_set_logfunc(context, NULL,
	    	GETDNS_LOG_UPSTREAM_STATS, (int)log_level, stubby_log);
	}

	(void) parse_config(default_config);
	if (custom_config_fn) {
		if ((r = parse_config_file(custom_config_fn))) {
			fprintf(stderr, "Could not parse config file "
			        "\"%s\": %s\n", custom_config_fn,
			        _getdns_strerror(r));
			return r;
		}
	} else {
		fn_sz = snprintf( home_stubby_conf_fn_spc
				, sizeof(home_stubby_conf_fn_spc)
				, "%s/.stubby.conf"
				, getenv("HOME")
				);

		if (fn_sz > 0 && fn_sz < (int)sizeof(home_stubby_conf_fn_spc))
			home_stubby_conf_fn = home_stubby_conf_fn_spc;

		else if (fn_sz > 0) {
			if (!(home_stubby_conf_fn = malloc(fn_sz + 1)) ||
			    snprintf( home_stubby_conf_fn, fn_sz
				    , "%s/.stubby.conf", getenv("HOME")) != fn_sz) {
				if (home_stubby_conf_fn) {
					free(home_stubby_conf_fn);
					home_stubby_conf_fn = NULL;
				}
			}
		}
		if (home_stubby_conf_fn &&
		    (r = parse_config_file(home_stubby_conf_fn))) {
			if (r != GETDNS_RETURN_IO_ERROR)
				fprintf( stderr, "Error parsing config file "
				         "\"%s\": %s\n", home_stubby_conf_fn
				       , _getdns_strerror(r));
			if (home_stubby_conf_fn != home_stubby_conf_fn_spc)
				free(home_stubby_conf_fn);
			home_stubby_conf_fn = NULL;
		}
		if (!home_stubby_conf_fn &&
		    (r = parse_config_file(STUBBYCONFDIR"/stubby.conf"))) {
			if (r != GETDNS_RETURN_IO_ERROR) {
				fprintf( stderr, "Error parsing config file \"%s\": %s\n"
			            , STUBBYCONFDIR"/stubby.conf"
			            , _getdns_strerror(r));
			}
			fprintf(stderr, "WARNING: No Stubby config file found... using minimal default config (Opportunistic Usage)\n");
		}
		if (home_stubby_conf_fn &&
		    home_stubby_conf_fn != home_stubby_conf_fn_spc) {
			free(home_stubby_conf_fn);
		}
	}
	if ((r = getdns_context_set_resolution_type(context, GETDNS_RESOLUTION_STUB))) {
		fprintf( stderr, "Error while trying to configure stubby for "
		                 "stub resolution only: %s\n", _getdns_strerror(r));
		exit(EXIT_FAILURE);
	}
	if (listen_count && (r = getdns_context_set_listen_addresses(
	    context, listen_list, NULL, incoming_request_handler)))
		perror("error: Could not bind on given addresses");
	else if (print_api_info) {
		getdns_dict *api_information = 
		    getdns_context_get_api_information(context);
		char *api_information_str;
	       
		if (listen_dict && !getdns_dict_get_list(
		    listen_dict, "listen_list", &listen_list)) {

			(void) getdns_dict_set_list(api_information,
			    "listen_addresses", listen_list);
		} else if (listen_list) {
			(void) getdns_dict_set_list(api_information,
			    "listen_addresses", listen_list);

		} else if ((listen_list = getdns_list_create())) {
			(void) getdns_dict_set_list(api_information,
			    "listen_addresses", listen_list);
			getdns_list_destroy(listen_list);
			listen_list = NULL;
		}
		api_information_str =
		    getdns_pretty_print_dict(api_information);
		fprintf(stdout, "%s\n", api_information_str);
		free(api_information_str);
		getdns_dict_destroy(api_information);
	}
	else
#ifndef STUBBY_ON_WINDOWS
	     if (!run_in_foreground) {
		pid_t pid;
		char pid_str[1024], *endptr;
		FILE *fh = fopen(STUBBYPIDFILE, "r");
		do {
			pid_t running;

			if (!fh || !fgets(pid_str, sizeof(pid_str), fh))
				break;

			running = strtol(pid_str, &endptr, 10);
			if (endptr == pid_str)
				break;

			if (kill(running, 0) < 0 && errno == ESRCH)
				break;

			fprintf( stderr, "Not starting because a running "
			        "stubby was found on pid: %d\n", running);
			exit(EXIT_FAILURE);
		} while(0);
		if (fh)
			(void) fclose(fh);

		pid = fork();
		if (pid == -1) {
			perror("Could not fork of stubby daemon\n");
			r = GETDNS_RETURN_GENERIC_ERROR;

		} else if (pid) {
			fh = fopen(STUBBYPIDFILE, "w");
			if (fh) {
				fprintf(fh, "%d", (int)pid);
				fclose(fh);
			} else {
				fprintf(stderr, "Could not write pid to "
				        "\"%s\": %s\n", STUBBYPIDFILE,
				        strerror(errno));
				exit(EXIT_FAILURE);
			}
		} else
			getdns_context_run(context);
	} else
#endif
	{
		stubby_local_log(NULL,GETDNS_LOG_UPSTREAM_STATS, GETDNS_LOG_DEBUG,
			       "Starting DAEMON....\n");
		getdns_context_run(context);
	}

	getdns_context_destroy(context);

	if (listen_list)
		getdns_list_destroy(listen_list);

	return r;
}
