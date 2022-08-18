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

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

#include "configfile.h"
#include "log.h"
#include "server.h"
#include "util.h"

static int dnssec_validation = 0;

#if defined(STUBBY_ON_WINDOWS)
#define DEBUG_ON(...) do { \
                        struct timeval tv_dEbUgSyM; \
                        struct tm tm_dEbUgSyM; \
                        char buf_dEbUgSyM[10]; \
                        time_t tsec_dEbUgSyM; \
                        \
                        gettimeofday(&tv_dEbUgSyM, NULL); \
                        tsec_dEbUgSyM = (time_t) tv_dEbUgSyM.tv_sec; \
                        gmtime_s(&tm_dEbUgSyM, (const time_t *) &tsec_dEbUgSyM); \
                        strftime(buf_dEbUgSyM, 10, "%H:%M:%S", &tm_dEbUgSyM); \
                        fprintf(stderr, "[%s.%.6d] ", buf_dEbUgSyM, (int)tv_dEbUgSyM.tv_usec); \
                        fprintf(stderr, __VA_ARGS__); \
                } while (0)
#else
#define DEBUG_ON(...) do { \
                        struct timeval tv_dEbUgSyM; \
                        struct tm tm_dEbUgSyM; \
                        char buf_dEbUgSyM[10]; \
                        \
                        gettimeofday(&tv_dEbUgSyM, NULL); \
                        gmtime_r(&tv_dEbUgSyM.tv_sec, &tm_dEbUgSyM); \
                        strftime(buf_dEbUgSyM, 10, "%H:%M:%S", &tm_dEbUgSyM); \
                        fprintf(stderr, "[%s.%.6d] ", buf_dEbUgSyM, (int)tv_dEbUgSyM.tv_usec); \
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

typedef struct dns_msg {
        getdns_transaction_t  request_id;
        getdns_dict          *request;
        getdns_resolution_t   rt;
        uint32_t              ad_bit;
        uint32_t              do_bit;
        uint32_t              cd_bit;
        int                   has_edns0;
} dns_msg;

#if defined(SERVER_DEBUG) && SERVER_DEBUG
#define SERVFAIL(error,r,msg,resp_p) do { \
        if (r)  DEBUG_SERVER("%s: %s\n", error, stubby_getdns_strerror(r)); \
        else    DEBUG_SERVER("%s\n", error); \
        servfail(msg, resp_p); \
        } while (0)
#else
#define SERVFAIL(error,r,msg,resp_p) servfail(msg, resp_p)
#endif

static void servfail(dns_msg *msg, getdns_dict **resp_p)
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

static void error_reply(dns_msg *msg, getdns_dict **resp_p, unsigned error)
{
	unsigned rcode, ex_rcode;
        getdns_dict *dict;
	getdns_list *list;

	rcode= error & 0xf;	/* Lowest 4 bits */
	ex_rcode= (error >> 4);	/* Higher 8 bits */

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
            *resp_p, "/header/rcode", rcode);
        (void) getdns_dict_set_int(*resp_p, "/header/qr", 1);
        (void) getdns_dict_set_int(*resp_p, "/header/ad", 0);

	if (ex_rcode)
	{
		dict= getdns_dict_create();
		getdns_dict_set_int(dict, "do", 0);
		getdns_dict_set_int(dict, "extended_rcode", ex_rcode);
		getdns_dict_set_int(dict, "type", GETDNS_RRTYPE_OPT);
		getdns_dict_set_int(dict, "udp_payload_size", 1232);
		getdns_dict_set_int(dict, "version", 0);
		getdns_dict_set_int(dict, "z", 0);
		list= getdns_list_create();
		getdns_list_set_dict(list, 0, dict);
		getdns_dict_set_list(*resp_p, "additional", list);
	}
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
        uint32_t n, rcode, dnssec_status = GETDNS_DNSSEC_INDETERMINATE;
        getdns_list *options;
        size_t n_options;
        uint32_t arcount;
        char i_as_jptr[80];

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
                    (int)callback_type, msg, &response);

        else if (!response)
                SERVFAIL("Missing response", 0, msg, &response);

        else if ((r = getdns_dict_get_int(msg->request, "/header/id", &qid)) ||
            (r=getdns_dict_set_int(response,"/replies_tree/0/header/id",qid)))
                SERVFAIL("Could not copy QID", r, msg, &response);

        else if (getdns_dict_get_int(
            response, "/replies_tree/0/header/rcode", &rcode))
                SERVFAIL("No reply in replies tree", 0, msg, &response);

        /* answers when CD or not BOGUS */
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

        /* AD when (DO or AD) and SECURE (But only when we perform validation natively) */
        else if (dnssec_validation &&
            (r = getdns_dict_set_int(response,"/replies_tree/0/header/ad",
            ((msg->do_bit || msg->ad_bit)
            && (  (!msg->cd_bit && dnssec_status == GETDNS_DNSSEC_SECURE)
               || ( msg->cd_bit && !getdns_dict_get_int(response,
                    "/replies_tree/0/dnssec_status", &dnssec_status)
                  && dnssec_status == GETDNS_DNSSEC_SECURE ))) ? 1 : 0)))
                SERVFAIL("Could not set AD bit", r, msg, &response);

        else if ((dnssec_validation || msg->rt == GETDNS_RESOLUTION_RECURSING)
            && (r =  getdns_dict_set_int(
            response, "/replies_tree/0/header/cd", msg->cd_bit)))
                SERVFAIL("Could not copy CD bit", r, msg, &response);

        else if (msg->rt == GETDNS_RESOLUTION_STUB)
                ; /* following checks are for RESOLUTION_RECURSING only */

        else if ((r = getdns_dict_get_int(
            response, "/replies_tree/0/header/ra", &n)))
                SERVFAIL("Could not get RA bit from reply", r, msg, &response);

        else if (n == 0)
                SERVFAIL("Recursion not available", 0, msg, &response);

        if (!getdns_dict_get_int(response, "/replies_tree/0/header/arcount", &arcount)
        &&  arcount > 0
        &&  snprintf( i_as_jptr, sizeof(i_as_jptr)
                    , "/replies_tree/0/additional/%d/rdata/options"
                    , (int)(arcount - 1))
        &&  !getdns_dict_get_list(response, i_as_jptr, &options)
        &&  !getdns_list_get_length(options, &n_options)) {
                int i;
                int options_changed = 0;

                for (i = 0; i < (int)n_options; i++) {
                        getdns_dict *option;
                        uint32_t option_code;
                        uint8_t a_byte;
                        uint16_t a_word;

                        (void) snprintf(i_as_jptr, sizeof(i_as_jptr),
                            "/replies_tree/0/additional/%d/rdata/options/%d",
                            (int)(arcount - 1), i);

                        if (getdns_dict_get_dict(response, i_as_jptr, &option)
                        ||  getdns_dict_get_int(option, "option_code", &option_code))
                                continue;

                        switch (option_code) {
                        case  8: /* CLIENT SUBNET */
                                if (getdns_context_get_edns_client_subnet_private
                                    (context, &a_byte) || !a_byte)
                                        continue;
                                break;
                        case 11: /* KeepAlive (remove always) */
                                break;
                        case 12: /* Padding */
                                if (getdns_context_get_tls_query_padding_blocksize
                                    (context, &a_word) || !a_word)
                                        continue;
                                break;
                        default:
                                continue;
                        }
                        if (!getdns_dict_remove_name(response, i_as_jptr)) {
                                options_changed++;
                                i -= 1;
                                n_options -= 1;
                        }
                }
                if (options_changed) {
                        (void) snprintf( i_as_jptr, sizeof(i_as_jptr)
                                       , "/replies_tree/0/additional/%d/rdata/rdata_raw"
                                       , (int)(arcount - 1));
                        (void) getdns_dict_remove_name(response, i_as_jptr);
                }
        }
        if ((r = getdns_reply(context, response, msg->request_id))) {
                stubby_error("Could not reply: %s", stubby_getdns_strerror(r));
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

#include <arpa/inet.h>

#define MAX_PROXY_CONTROL_OPTS	10
#define PROXY_ADDRS_MAX 10

static struct upstream
{
	unsigned dns_error;
	unsigned opts_count;
	struct proxy_opt
	{
		/* Original bindata of option */
		getdns_bindata bindata;

		/* Decoded option */
		uint16_t flags1;
		uint16_t flags2;
		int addr_count;
		struct sockaddr_storage addrs[PROXY_ADDRS_MAX];

		/* Getdns context */
		getdns_context *context;
	} opts[MAX_PROXY_CONTROL_OPTS];
} *upstreams;
static int upstreams_count;

static struct upstream *get_upstreams_for_policy(getdns_dict *opt_rr);

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
	unsigned dns_error = GETDNS_RCODE_SERVFAIL;
	struct upstream *usp;

        (void)callback_type;
        (void)userarg;

	printf("incoming_request_handler: got request %s\n",
		getdns_pretty_print_dict(request));

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
	usp= NULL;
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

			usp= get_upstreams_for_policy(rr);

                        break;
                }
        }

	if (usp && usp->dns_error)
	{
		dns_error= usp->dns_error;
		goto error;
	}

        if ((r = getdns_context_get_resolution_type(context, &msg->rt)))
                stubby_error("Could get resolution type from context: %s",
                    stubby_getdns_strerror(r));

        if (msg->rt == GETDNS_RESOLUTION_STUB) {
                (void)getdns_dict_set_int(
                    qext , "/add_opt_parameters/do_bit", msg->do_bit);
                if (!getdns_dict_get_dict(request, "header", &header))
                        (void)getdns_dict_set_dict(qext, "header", header);

        }
        if (msg->cd_bit && dnssec_validation)
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
                stubby_error("Could not get qname from query: %s",
                    stubby_getdns_strerror(r));

        else if ((r = getdns_convert_dns_name_to_fqdn(qname, &qname_str)))
                stubby_error("Could not convert qname: %s",
                    stubby_getdns_strerror(r));

        else if ((r=getdns_dict_get_int(request,"/question/qtype",&qtype)))
                stubby_error("Could get qtype from query: %s",
                    stubby_getdns_strerror(r));

        else if ((r=getdns_dict_get_int(request,"/question/qclass",&qclass)))
                stubby_error("Could get qclass from query: %s",
                    stubby_getdns_strerror(r));

        else if ((r = getdns_dict_set_int(qext, "specify_class", qclass)))
                stubby_error("Could set class from query: %s",
                    stubby_getdns_strerror(r));

        else if ((r = getdns_general(context, qname_str, qtype,
            qext, msg, &transaction_id, request_cb)))
                stubby_error("Could not schedule query: %s",
                    stubby_getdns_strerror(r));
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
	if (dns_error == GETDNS_RCODE_SERVFAIL)
        	servfail(msg, &response);
	else
		error_reply(msg, &response, dns_error);
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
                stubby_error("Could not reply: %s",
                    stubby_getdns_strerror(r));
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

#define OPT_PROXY_CONTROL 42

static void decode_proxy_option(struct proxy_opt *opt);
static void setup_upstream(struct upstream *usp);

static struct upstream *get_upstreams_for_policy(getdns_dict *opt_rr)
{
	int i;
	unsigned u, proxy_control_opts_count;
	uint32_t option_code;
	size_t list_count, size;
	getdns_list *opt_list;
	getdns_dict *opt_dict;
	struct upstream *new_upstreams, *usp;
	void *data;
	getdns_bindata *proxy_control_opts[MAX_PROXY_CONTROL_OPTS];

	proxy_control_opts_count= 0;
	if (getdns_dict_get_list(opt_rr, "/rdata/options", &opt_list) !=
		GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"get_upstreams_for_policy: no options, should use default\n");
		abort();
	}

	if (getdns_list_get_length(opt_list, &list_count) !=
		GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"get_upstreams_for_policy: can't get lenght of list\n");
		abort();
	}
	for (u= 0; u<list_count; u++)
	{
		if (getdns_list_get_dict(opt_list, u, &opt_dict) !=
			GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"get_upstreams_for_policy: can't get dict from list\n");
			abort();
		}
		if (getdns_dict_get_int(opt_dict, "option_code",
			&option_code) != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"get_upstreams_for_policy: can't get option_code\n");
			abort();
		}
		if (option_code != OPT_PROXY_CONTROL)
			continue;

		if (proxy_control_opts_count >= MAX_PROXY_CONTROL_OPTS)
		{
			fprintf(stderr, "get_upstreams_for_policy: too many options in request, should return error\n");
			abort();
		}

		if (getdns_dict_get_bindata(opt_dict, "option_data",
			&proxy_control_opts[proxy_control_opts_count]) !=
			GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"get_upstreams_for_policy: can't get option_data\n");
			abort();
		}

		proxy_control_opts_count++;

	}

	if (!proxy_control_opts_count)
	{
		fprintf(stderr,
		"get_upstreams_for_policy: no options, should use default\n");
		abort();
	}

	/* Try to find an existing upstream */
	for (i= 0, usp= upstreams; i<upstreams_count; i++, usp++)
	{
		if (usp->opts_count != proxy_control_opts_count)
			continue;
		for (u= 0; u<proxy_control_opts_count; u++)
		{
			size= proxy_control_opts[u]->size;
			if (size != usp->opts[u].bindata.size)
				break;
			if (size && memcmp(proxy_control_opts[u]->data,
				usp->opts[u].bindata.data, size) != 0)
			{
				break;
			}
		}
		if (u != proxy_control_opts_count)
		{
			/* No match */
			continue;
		}
		return usp;
	}

	new_upstreams= realloc(upstreams,
		(upstreams_count+1)*sizeof(upstreams[0]));
	upstreams= new_upstreams;
	usp= &upstreams[upstreams_count];
	usp->opts_count= proxy_control_opts_count;
	for (u= 0; u<proxy_control_opts_count; u++)
	{
		size= proxy_control_opts[u]->size;
		if (size)
		{
			data= malloc(size);
			memcpy(data, proxy_control_opts[u]->data, size);
		}
		else
			data= NULL;

		usp->opts[u].bindata.data= data;
		usp->opts[u].bindata.size= size;

		decode_proxy_option(&usp->opts[u]);
		setup_upstream(usp);
	}
	upstreams_count++;

	return usp;
}

static void decode_proxy_option(struct proxy_opt *opt)
{
	uint8_t addr_type, addr_length, name_length, svc_length, inf_length;
	uint16_t u16;
	int i;
	size_t o, size;
	uint8_t *p;
	struct sockaddr_in6 *sin6p;

	size= opt->bindata.size;
	p= opt->bindata.data;

	if (size < 2)
		goto error;

	memcpy(&u16, p, 2);
	opt->flags1= ntohs(u16);

	p += 2;
	size -= 2;

	if (size < 2)
		goto error;

	memcpy(&u16, p, 2);
	opt->flags2= ntohs(u16);

	p += 2;
	size -= 2;

	if (size < 2)
		goto error;

	addr_type= p[0];
	addr_length= p[1];

	p += 2;
	size -= 2;

	opt->addr_count= 0;
	if (addr_length)
	{
		if (size < addr_length)
			goto error;
		
		switch(addr_type)
		{
		case 2:
			if (addr_length >
				PROXY_ADDRS_MAX*sizeof(struct in6_addr))
			{
				fprintf(stderr,
			"decode_proxy_option: more addresses than supported\n");
				goto error;
			}
			for(o= 0, i= 0;
				o+sizeof(struct in6_addr) <= addr_length;
				o += sizeof(struct in6_addr), i++)
			{
				sin6p= (struct sockaddr_in6 *)
					&opt->addrs[i];
				sin6p->sin6_family= AF_INET6;
				memcpy(&sin6p->sin6_addr,
					p+o, sizeof(struct in6_addr));
			}
			if (o != addr_length)
			{
				fprintf(stderr,
			"decode_proxy_option: bad addr_length\n");
				goto error;
			}
			opt->addr_count= i;
			break;

		default:
			fprintf(stderr,
				"decode_proxy_option: unknown addr_type %d\n",
				addr_type);
			goto error;
		}
		p += addr_length;
		size -= addr_length;
	}

	if (size < 1)
		goto error;

	name_length= p[0];

	p += 1;
	size -= 1;

	if (name_length)
	{
		fprintf(stderr, "decode_proxy_option: should handle name\n");

		p += name_length;
		size -= name_length;
	}

	if (size < 1)
		goto error;

	svc_length= p[0];

	p += 1;
	size -= 1;

	if (svc_length)
	{
		fprintf(stderr, "decode_proxy_option: should handle svc\n");

		p += svc_length;
		size -= svc_length;
	}

	if (size < 1)
		goto error;

	inf_length= p[0];

	p += 1;
	size -= 1;

	if (inf_length)
	{
		fprintf(stderr, "decode_proxy_option: should handle inf\n");

		p += inf_length;
		size -= inf_length;
	}

	if (size != 0)
	{
		fprintf(stderr,
			"decode_proxy_option: garbage at end of option\n");
		goto error;
	}
	return;
	
error:
	fprintf(stderr, "decode_proxy_option: should handle error\n");
	abort();
}

#define PROXY_CONTROL_FLAG_U	(1 << 15)
#define PROXY_CONTROL_FLAG_UA	(1 << 14)
#define PROXY_CONTROL_FLAG_A	(1 << 13)
#define PROXY_CONTROL_FLAG_P	(1 << 12)
#define PROXY_CONTROL_FLAG_D	(1 << 11)

#define BADPROXYPOLICY	42

static void setup_upstream(struct upstream *usp)
{
	int r;
	unsigned u, U_flag, UA_flag, A_flag, P_flag, D_flag;
	size_t transports_count;
	struct proxy_opt *po;
	getdns_context *context;
	getdns_transport_list_t transports[3];

	usp->dns_error= 0;
	for (u= 0, po= usp->opts; u<usp->opts_count; u++, po++)
	{
		/* Check U, UA, and A flags */
		U_flag= !!(po->flags1 & PROXY_CONTROL_FLAG_U);
		UA_flag= !!(po->flags1 & PROXY_CONTROL_FLAG_UA);
		A_flag= !!(po->flags1 & PROXY_CONTROL_FLAG_A);
		if (U_flag + UA_flag + A_flag > 1)
		{
			fprintf(stderr,
				"setup_upstream: too many of U, UA, A\n");
			usp->dns_error= BADPROXYPOLICY;
			goto error;
		}
		if (U_flag + UA_flag + A_flag == 0)
		{
			/* No preference. Select GETDNS_TRANSPORT_TLS 
			 * followed by GETDNS_TRANSPORT_UDP and
			 *  GETDNS_TRANSPORT_TCP
			 */
			transports[0]= GETDNS_TRANSPORT_TLS;
			transports[1]= GETDNS_TRANSPORT_UDP;
			transports[2]= GETDNS_TRANSPORT_TCP;
			transports_count= 3;
		}
		else if (U_flag)
		{
			/* Only unencrypted. Select GETDNS_TRANSPORT_UDP
			 * followed by GETDNS_TRANSPORT_TCP
			 */
			transports[0]= GETDNS_TRANSPORT_UDP;
			transports[1]= GETDNS_TRANSPORT_TCP;
			transports_count= 2;
		}
		else if (UA_flag)
		{
			/* Only unauthenticated. Select GETDNS_TRANSPORT_TLS
			 */
			transports[0]= GETDNS_TRANSPORT_TLS;
			transports_count= 1;
		}
		else if (A_flag)
		{
			fprintf(stderr,
		"setup_upstream: authentication not supported by getdns\n");
			usp->dns_error= BADPROXYPOLICY;
			goto error;
		}
		else
		{
			fprintf(stderr, "setup_upstream: weird state\n");
			abort();
		}

		/* P and D flags can only be set if the A flag is set. */
		P_flag= !!(po->flags1 & PROXY_CONTROL_FLAG_P);
		D_flag= !!(po->flags1 & PROXY_CONTROL_FLAG_D);
fprintf(stderr, "setup_upstream: flags1 0x%x, P_flag %d, D_flag %d\n", po->flags1, P_flag, D_flag);
		if ((P_flag || D_flag) && !A_flag)
		{
			fprintf(stderr, "setup_upstream: P or D but not A\n");
			usp->dns_error= BADPROXYPOLICY;
			goto error;
		}
		if ((r = getdns_context_create(&context, 1 /*set_from_os*/))
			!= GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
			"setup_upstream: getdns_context_create failed\n");
			abort();
		}
		po->context = context;
		if ((r = getdns_context_set_dns_transport_list(context,
			transports_count, transports)) != GETDNS_RETURN_GOOD)

		{
			fprintf(stderr,
				"setup_upstream: cannot set transports\n");
			abort();
		}
	}
	fprintf(stderr, "setup_upstream: not finished\n");
	abort();
#if 0
static struct upstream
{
	unsigned opts_count;
	struct proxy_opt
	{
		/* Original bindata of option */
		getdns_bindata bindata;

		/* Decoded option */
		uint16_t flags1;
		uint16_t flags2;
		int addr_count;
		struct sockaddr_storage addrs[PROXY_ADDRS_MAX];
	} opts[MAX_PROXY_CONTROL_OPTS];
} *upstreams;
#endif
error:
	fprintf(stderr,
		"setup_upstream: error, should clear getdns contexts\n");
}

int server_listen(getdns_context *context, int validate_dnssec)
{
        const getdns_list *listen_list;

        dnssec_validation = validate_dnssec;

        listen_list = get_config_listen_list();
        if ( !listen_list )
                return 0;
        if ( getdns_context_set_listen_addresses(
                     context, listen_list, NULL, incoming_request_handler) ) {
                stubby_error("error: Could not bind on given addresses: %s", strerror(errno));
                return 0;
        }

        return 1;
}
