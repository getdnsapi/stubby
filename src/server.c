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
	struct upstream       *upstream;
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
	getdns_list *list;
	getdns_dict *new_resp;

        if (!(new_resp = getdns_dict_create())) {
                getdns_dict_destroy(*resp_p);
		*resp_p = NULL;
                return;
	}
        if (msg) {
                if (!getdns_dict_get_dict(msg->request, "header", &dict))
                        getdns_dict_set_dict(new_resp, "header", dict);
                if (!getdns_dict_get_dict(msg->request, "question", &dict))
                        getdns_dict_set_dict(new_resp, "question", dict);
                (void) getdns_dict_set_int(new_resp, "/header/ra",
                    msg->rt == GETDNS_RESOLUTION_RECURSING ? 1 : 0);
        }
        (void) getdns_dict_set_int(
            new_resp, "/header/rcode", GETDNS_RCODE_SERVFAIL);
        (void) getdns_dict_set_int(new_resp, "/header/qr", 1);
        (void) getdns_dict_set_int(new_resp, "/header/ad", 0);
	if (!getdns_dict_get_list(*resp_p, "call_reporting", &list))
		getdns_dict_set_list(new_resp, "call_reporting", list);
	getdns_dict_destroy(*resp_p);
	*resp_p = new_resp;
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

static void response_add_proxy_option(getdns_dict *response, uint8_t *buf,
	size_t bufsize);

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
	static uint8_t optbuf[2048];

	fprintf(stderr, "request_cb: got context %p\n",
		(void *)context);
	fprintf(stderr, "request_cb: got response %s\n",
		getdns_pretty_print_dict(response));

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

	if (msg->upstream)
	{
		response_add_proxy_option(response, optbuf, sizeof(optbuf));
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
#define PROXY_ADDRS_MAX 	10
#define ALPN_MAX		10

struct incoming_request {
	getdns_context          *down_context;
	getdns_callback_type_t   callback_type;
	getdns_dict             *request;
	void                    *userarg;
	getdns_transaction_t     request_id;
	struct incoming_request *next;
};

/* Values for target and status */
#define TS_NOT_STARTED		1
#define TS_FAILED		2
#define TS_UNENCRYPTED		3
#define TS_UNAUTHENTICATED	4
#define TS_OPPORTUNISTIC	5
#define TS_AUTHENTICATED	6

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
		char *name;
		int alpn_count;
		char *alpn[ALPN_MAX];
		int no_default_alpn;
		int addr_count;
		struct sockaddr_storage addrs[PROXY_ADDRS_MAX];
		uint16_t port;
		char *infname;

		/* Getdns context */
		getdns_context          *context;
		int                      ready;
		getdns_transaction_t     dane_request_id;
		struct incoming_request *incoming_requests;

		/* Current status */
		unsigned target;	/* Target authentication status of
					 * this getdns context.
					 */
		unsigned status;	/* Last known result */
	} opts[MAX_PROXY_CONTROL_OPTS];
	unsigned sorted[MAX_PROXY_CONTROL_OPTS];
} *upstreams;
static int upstreams_count;

static struct upstream *get_upstreams_for_policy(getdns_context *down_context,
	getdns_dict *opt_rr);

#define BADPROXYPOLICY	42

#define PROXY_CONTROL_FLAG1_U	(1 << 15)
#define PROXY_CONTROL_FLAG1_UA	(1 << 14)
#define PROXY_CONTROL_FLAG1_A	(1 << 13)
#define PROXY_CONTROL_FLAG1_P	(1 << 12)
#define PROXY_CONTROL_FLAG1_D	(1 << 11)
#define PROXY_CONTROL_FLAG1_DD	(1 << 10)

#define PROXY_CONTROL_FLAG2_A53	(1 << 15)
#define PROXY_CONTROL_FLAG2_D53	(1 << 14)
#define PROXY_CONTROL_FLAG2_AT	(1 << 13)
#define PROXY_CONTROL_FLAG2_DT	(1 << 12)
#define PROXY_CONTROL_FLAG2_AH2	(1 << 11)
#define PROXY_CONTROL_FLAG2_DH2	(1 << 10)
#define PROXY_CONTROL_FLAG2_AH3	(1 <<  9)
#define PROXY_CONTROL_FLAG2_DH3	(1 <<  8)
#define PROXY_CONTROL_FLAG2_AQ	(1 <<  7)
#define PROXY_CONTROL_FLAG2_DQ	(1 <<  6)


#define POLICY_N_ADDR		3
#define POLICY_N_SVCPARAMS	8

typedef struct getdns_proxy_policy {
	uint16_t flags1, flags2;
	int addr_count;
	struct sockaddr_storage addrs[POLICY_N_ADDR];
	char *domainname;
	struct
	{
		char *key;
		char *value;
	} svcparams[POLICY_N_SVCPARAMS];
	char *interface;
} getdns_proxy_policy;

static void proxy_policy2opt(getdns_proxy_policy *policy, int do_ipv6,
	uint8_t *buf, size_t *sizep);

static int select_upstream(struct upstream *usp);

static void incoming_request_handler(getdns_context *down_context,
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
        size_t i, len = 0;
        getdns_list *additional;
        getdns_dict *rr;
        uint32_t rr_type;
	unsigned dns_error = GETDNS_RCODE_SERVFAIL;
	int up_index;
	struct upstream *usp;
	getdns_context *up_context;

        (void)callback_type;
        (void)userarg;

	fprintf(stderr, "incoming_request_handler: got request %s\n",
		getdns_pretty_print_dict(request));

        if (!(qext = getdns_dict_create_with_context(down_context)) ||
            !(msg = malloc(sizeof(dns_msg))))
                goto error;

        /* pass through the header and the OPT record */
        n = 0;
        msg->request_id = request_id;
        msg->request = request;
        msg->ad_bit = msg->do_bit = msg->cd_bit = 0;
        msg->has_edns0 = 0;
        msg->rt = GETDNS_RESOLUTION_RECURSING;
	msg->upstream = NULL;
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

			fprintf(stderr,
"incoming_request_handler: options dict %s\n", getdns_pretty_print_dict(rr));
			fprintf(stderr,
"incoming_request_handler: calling get_upstreams_for_policy\n");
			usp= get_upstreams_for_policy(down_context, rr);
                        break;
                }
        }

	if (usp && usp->dns_error)
	{
		dns_error= usp->dns_error;

		/* Delete all options. Assume that options are not
		 * transitive. Some options may need to be copied.
		 */
		getdns_dict_remove_name(request, "/additional/0/rdata/options");
		goto error;
	}

	if (usp)
	{
		msg->upstream = usp;

		/* Only try first context */
		up_index = select_upstream(usp);
		fprintf(stderr, "incoming_request_handler: up_index %d\n", up_index);
		if (!usp->opts[up_index].ready) {
			struct incoming_request *ir;

			fprintf(stderr, "queueing incoming request waiting "
					"for upstream to get ready\n");
			getdns_dict_destroy(qext);
			free(msg);
			if (!(ir = malloc(sizeof(struct incoming_request))))
				goto error;
			ir->down_context  = down_context;
			ir->callback_type = callback_type;
			ir->request       = request;
			ir->userarg       = userarg;
			ir->request_id    = request_id;
			ir->next          = usp->opts[up_index].
						incoming_requests;
			usp->opts[up_index].incoming_requests = ir;
			return;
		}
		up_context = usp->opts[up_index].context;

        	if ((r = getdns_dict_set_int(qext, "return_call_reporting",
			GETDNS_EXTENSION_TRUE)))
		{
                	stubby_error("Could set return_call_reporting: %s",
                    		stubby_getdns_strerror(r));
		}
	}
	else
	{
		up_context = down_context;
		/* Delete all options. Assume that options are not
		 * transitive. Some options may need to be copied.
		 */
		getdns_dict_remove_name(request, "/additional/0/rdata/options");
	}

        if ((r = getdns_context_get_resolution_type(up_context, &msg->rt)))
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

	fprintf(stderr, "incoming_request_handler: using upstream context %p\n",
		(void *)up_context);

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

        else if ((r = getdns_general(up_context, qname_str, qtype,
            qext, msg, &transaction_id, request_cb)))
                stubby_error("Could not schedule query: %s",
                    stubby_getdns_strerror(r));
        else {
		fprintf(stderr, "incoming_request_handler: qext %s\n",
			getdns_pretty_print_dict(qext));
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
	fprintf(stderr, "incoming_request_handler: dns_error %d\n", dns_error);
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
        if ((r = getdns_reply(down_context, response, request_id))) {
                stubby_error("Could not reply: %s",
                    stubby_getdns_strerror(r));
                /* Cancel reply */
                getdns_reply(down_context, NULL, request_id);
        }
        if (msg) {
                if (msg->request)
                        getdns_dict_destroy(msg->request);
                free(msg);
        }
        if (response)
                getdns_dict_destroy(response);
}

static void dane_request_cb(
    getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t transaction_id)
{
        struct proxy_opt *po = (struct proxy_opt *)userarg;
        getdns_return_t r = GETDNS_RETURN_GOOD;
        uint32_t  rcode, dnssec_status, ancount;
	char *dict_str;
	getdns_list *upstreams;
	getdns_list *answers;

	/* unused parameters */
	(void)context; (void)callback_type; (void)transaction_id;

	if ((dict_str = getdns_pretty_print_dict(response))) {
		stubby_debug("dane_request_cb: got reponse %s\n", dict_str);
		free(dict_str);
	}
	if (!response
	||   getdns_dict_get_int( response, "/replies_tree/0/header/rcode"
				, &rcode)
	||   getdns_dict_get_int( response, "/replies_tree/0/dnssec_status"
				, &dnssec_status)
	||   getdns_dict_get_int( response, "/replies_tree/0/header/ancount"
				, &ancount)
	||   rcode         != GETDNS_RCODE_NOERROR
	||   dnssec_status != GETDNS_DNSSEC_SECURE
	||   ancount       <  2)
		stubby_debug("No suitable DANE records found\n");

	else if ((r = getdns_dict_get_list( response, "/replies_tree/0/answer"
	                                  , &answers)))
		stubby_error("Could not get answer section: %s\n"
		            , stubby_getdns_strerror(r));

	else if ((r = getdns_context_get_upstream_recursive_servers(po->context,
					&upstreams)))
		stubby_error("Could not get upstreams: %s\n"
		            , stubby_getdns_strerror(r));

	else {
		size_t i;
		getdns_dict *answer, *upstream;

		if (!(po->flags1 & PROXY_CONTROL_FLAG1_P)) {
			for (i = 0
			    ; !(r = getdns_list_get_dict(answers, i, &answer))
			    ; i += 1) {
				uint32_t usage;

				if (!getdns_dict_get_int(answer,
					    "/rdata/certificate_usage", &usage))
					getdns_dict_set_int(answer,
					    "/rdata/certificate_usage",
					    (usage & 1)
					    );
			}
			if (r != GETDNS_RETURN_NO_SUCH_LIST_ITEM)
				stubby_error("Enumerating answers error: %s"
					    , stubby_getdns_strerror(r));
		}
		for ( i = 0
		    ; !(r = getdns_list_get_dict(upstreams, i, &upstream))
		    ; i += 1)
			getdns_dict_set_list(upstream, "dane_records", answers);

		if (r != GETDNS_RETURN_NO_SUCH_LIST_ITEM)
			stubby_error("Enumerating upstreams error: %s"
			            , stubby_getdns_strerror(r));

		else if ((r = getdns_context_set_upstream_recursive_servers(
						po->context, upstreams)))
			stubby_error("Could not set upstreams: %s"
			            , stubby_getdns_strerror(r));
		else {
			char *upstreams_str = getdns_pretty_print_list(
					upstreams);
			if (upstreams_str) {
				stubby_debug("DANE upstreams: %s\n", 
						upstreams_str);
				free(upstreams_str);
			}
			po->ready = 1;
			/* resubmit requests for upstream */
			while (po->incoming_requests) {
				struct incoming_request *request
					= po->incoming_requests;
				struct incoming_request *next = request->next;

				incoming_request_handler( request->down_context
				                        , request->callback_type
				                        , request->request
				                        , request->userarg
				                        , request->request_id
				                        );
				free(request);
				po->incoming_requests = next;
			}
			return;
		}
	};
	/* TODO:
	 * - Either remove the upstream, or set a timer to retry after X minutes
	 */
	/* failed, cancel incoming_requests */
	if (!po->incoming_requests)
		stubby_debug("No incoming requests to cancel\n");

	else while (po->incoming_requests) {
		struct incoming_request *request = po->incoming_requests;
		struct incoming_request *next = request->next;
		getdns_dict *response = request->request;
		getdns_proxy_policy policy;
		uint8_t buf[2048];
		size_t bufsize = sizeof(buf);
		getdns_dict *opt_dict;
		getdns_bindata bindata;
		uint32_t rd;

		/* Turn request into error response
		 */
		getdns_dict_set_int(response, "/header/ra",
		    !getdns_dict_get_int(response, "/header/rd", &rd) ? rd : 0);
		getdns_dict_set_int(response, "/header/rcode",
		    GETDNS_RCODE_SERVFAIL);
		getdns_dict_set_int(response, "/header/qr", 1);
		getdns_dict_set_int(response, "/header/ad", 0);
		getdns_dict_set_int(response, "/header/arcount", 0);
		getdns_dict_remove_name(response, "/additional");

		policy.flags1 = 0;
		policy.flags2 = 0;
		policy.addr_count = po->addr_count;
		memcpy(policy.addrs, po->addrs, sizeof(policy.addrs));
		policy.domainname = po->name;
		policy.svcparams[0].key = NULL;
		policy.interface = po->infname;
		/* DANE for DoT for now */
		policy.flags2 |= PROXY_CONTROL_FLAG2_AT;
		/* DANE authentication failed, PKIX might still work */
		policy.flags1 |= PROXY_CONTROL_FLAG1_A;
		policy.flags1 |= PROXY_CONTROL_FLAG1_UA;
		policy.flags1 |= PROXY_CONTROL_FLAG1_DD;
		proxy_policy2opt(&policy, policy.addrs[0].ss_family == AF_INET6,
		    buf, &bufsize);
		if (getdns_str2dict( "{ do              : 1"
		                     ", extended_rcode  : 0"
		                     ", type            : GETDNS_RRTYPE_OPT"
		                     ", udp_payload_size: 512"
		                     ", version         : 0"
		                     ", z               : 0"
		                     ", rdata           :"
		                     "  { options: [ { option_code: 42 } ] }"
		                     "}"
	                           , &opt_dict) == GETDNS_RETURN_GOOD) {

			bindata.data = buf;
			bindata.size = bufsize;
			getdns_dict_set_bindata(opt_dict,
				"/rdata/options/0/option_data", &bindata);
			getdns_dict_set_dict(response,
				"/additional/-", opt_dict);
			getdns_dict_set_int(response, "/header/arcount", 1);
		}
		if ((dict_str = getdns_pretty_print_dict(response))) {
			stubby_debug("dane_request_cb: canceling incoming "
			             "request with: %s\n", dict_str);
			free(dict_str);
		}
		if ((r = getdns_reply( request->down_context, response
		                     , request->request_id))) {
                	stubby_error("Could not reply: %s"
			            , stubby_getdns_strerror(r));
                	/* Cancel reply */
                	getdns_reply( request->down_context, NULL
			            , request->request_id);
		}
		getdns_dict_destroy(response);
		free(request);
		po->incoming_requests = next;
	}
}

#define GLDNS_EDNS_PROXY_CONTROL	42
#define SVC_KEY_MANDATORY	0
#define SVC_KEY_ALPN		1
#define SVC_KEY_NDA		2
#define SVC_KEY_PORT		3

static int decode_proxy_option(struct proxy_opt *opt);
static void setup_upstream(getdns_context *down_context, struct upstream *usp);

static struct upstream *get_upstreams_for_policy(getdns_context *down_context,
	getdns_dict *opt_rr)
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
		if (option_code != GLDNS_EDNS_PROXY_CONTROL)
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

		fprintf(stderr,
		"get_upstreams_for_policy: calling decode_proxy_option\n");
		if (!decode_proxy_option(&usp->opts[u]))
		{
			usp->dns_error = BADPROXYPOLICY;
			break;
		}
	}
	fprintf(stderr, "get_upstreams_for_policy: calling setup_upstream\n");
	setup_upstream(down_context, usp);

	upstreams_count++;

	return usp;
}

static int decode_proxy_option(struct proxy_opt *opt)
{
	uint8_t addr_type, addr_length, name_length, svc_length, inf_length;
	uint16_t u16, svc_key, svc_val_len;
	int i;
	size_t o, oa, ol, llen, no, size;
	uint8_t *p;
	struct sockaddr_in *sin4p;
	struct sockaddr_in6 *sin6p;
	char *alpn;

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
		case 1:
			if (addr_length >
				PROXY_ADDRS_MAX*sizeof(struct in_addr))
			{
				fprintf(stderr,
			"decode_proxy_option: more addresses than supported\n");
				goto error;
			}
			for(o= 0, i= 0;
				o+sizeof(struct in_addr) <= addr_length;
				o += sizeof(struct in_addr), i++)
			{
				sin4p= (struct sockaddr_in *)
					&opt->addrs[i];
				sin4p->sin_family= AF_INET;
				memcpy(&sin4p->sin_addr,
					p+o, sizeof(struct in_addr));
			}
			if (o != addr_length)
			{
				fprintf(stderr,
			"decode_proxy_option: bad addr_length\n");
				goto error;
			}
			opt->addr_count= i;
			break;

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

	opt->name= NULL;
	if (name_length)
	{
		/* Assume that the decoded name fits in a buffer sized
		 * name_length
		 */
		opt->name = malloc(name_length);
		o = 0;
		no = 0;
		while (o < name_length)
		{
			llen = p[o];
			o++;
			if (o + llen > name_length)
				goto error;
			if (llen)
			{
				memcpy(opt->name+no, p+o, llen);
				no += llen;
				opt->name[no] = '.';
				no++;
			}
			o += llen;
		}
		if (no == 0)
		{
			/* Add a '.' */
			opt->name[no] = '.';
			no++;
		}
		if (no > 0 && opt->name[no-1] == '.')
			no--;	/* Remove trailing dot */
		opt->name[no] = '\0';

		p += name_length;
		size -= name_length;
	}

	if (size < 1)
		goto error;

	svc_length= p[0];

	p += 1;
	size -= 1;

	opt->alpn_count = 0;
	opt->no_default_alpn = 0;
	opt->port = 0;
	if (svc_length)
	{
		o = 0;
		while (o < svc_length)
		{
			if (o+2 > svc_length)
				goto error;
			memcpy(&u16, p+o, 2);
			o += 2;
			svc_key = ntohs(u16);
			if (o+2 > svc_length)
				goto error;
			memcpy(&u16, p+o, 2);
			o += 2;
			svc_val_len = ntohs(u16);
			if (o+svc_val_len > svc_length)
				goto error;

			switch(svc_key)
			{
			case SVC_KEY_MANDATORY:
				oa = 0;
				while (oa < svc_val_len)
				{
					if (oa + 2 > svc_val_len)
						goto error;
					memcpy(&u16, p+o+oa, sizeof(u16));
					u16 = ntohs(u16);
					switch(u16)
					{
					case SVC_KEY_ALPN:
					case SVC_KEY_NDA:
					case SVC_KEY_PORT:
						/* Keys that we know */
						break;
					default:
						fprintf(stderr,
			"decode_proxy_option: unknown mandatory key %u\n",
							u16);
						goto error;
					}
					oa += 2;
				}
				break;

			case SVC_KEY_ALPN:
				oa = 0;
				while (oa < svc_val_len)
				{
					if (opt->alpn_count >= ALPN_MAX)
						goto error;
					if (oa + 1 > svc_val_len)
						goto error;
					ol = p[o+oa];
					oa++;
					if (oa + ol > svc_val_len)
						goto error;
					alpn = malloc(ol+1);
					memcpy(alpn, p+o+oa, ol);
					oa += ol;
					alpn[ol] = '\0';
					opt->alpn[opt->alpn_count++] = alpn;
				}
				break;

			case SVC_KEY_NDA:
				if (svc_val_len != 0)
					goto error;
				opt->no_default_alpn = 1;
				break;

			case SVC_KEY_PORT:
				if (svc_val_len != 2)
					goto error;
				memcpy(&u16, p+o, 2);
				opt->port = ntohs(u16);
				break;

			default:
				fprintf(stderr,
			"decode_proxy_option: unknown SVC parameter key %d\n",
					svc_key);
				break;
			}
			o += svc_val_len;
		}

		p += svc_length;
		size -= svc_length;
	}

	if (size < 1)
		goto error;

	inf_length= p[0];

	p += 1;
	size -= 1;

	opt->infname = NULL;
	if (inf_length)
	{
		opt->infname = malloc(inf_length+1);
		memcpy(opt->infname, p, inf_length);
		opt->infname[inf_length] = '\0';

		p += inf_length;
		size -= inf_length;
	}

	if (size != 0)
	{
		fprintf(stderr,
			"decode_proxy_option: garbage at end of option\n");
		goto error;
	}
	return 1;
	
error:
	return 0;
}

#define PROXY_CONTROL_FLAG1_U	(1 << 15)
#define PROXY_CONTROL_FLAG1_UA	(1 << 14)
#define PROXY_CONTROL_FLAG1_A	(1 << 13)
#define PROXY_CONTROL_FLAG1_P	(1 << 12)
#define PROXY_CONTROL_FLAG1_D	(1 << 11)
#define PROXY_CONTROL_FLAG1_DD	(1 << 10)

#define PROXY_CONTROL_FLAG2_A53	(1 << 15)
#define PROXY_CONTROL_FLAG2_D53	(1 << 14)
#define PROXY_CONTROL_FLAG2_AT	(1 << 13)
#define PROXY_CONTROL_FLAG2_DT	(1 << 12)
#define PROXY_CONTROL_FLAG2_AH2	(1 << 11)
#define PROXY_CONTROL_FLAG2_DH2	(1 << 10)
#define PROXY_CONTROL_FLAG2_AH3	(1 <<  9)
#define PROXY_CONTROL_FLAG2_DH3	(1 <<  8)
#define PROXY_CONTROL_FLAG2_AQ	(1 <<  7)
#define PROXY_CONTROL_FLAG2_DQ	(1 <<  6)

static int opt_cmp(const void *v1, const void *v2);

struct sort_help
{
	struct upstream *usp;
	unsigned index;
};

static void setup_upstream(getdns_context *down_context, struct upstream *usp)
{
	int i, j, r;
	unsigned u, U_flag, UA_flag, A_flag, P_flag, D_flag, DD_flag;
	unsigned A53_flag, D53_flag, AT_flag, DT_flag, AH2_flag, DH2_flag,
		AH3_flag, DH3_flag, AQ_flag, DQ_flag;
	unsigned do_Do53, do_DoT, do_DoH2;
	size_t transports_count;
	struct proxy_opt *po;
	getdns_context *up_context;
	getdns_list *list, *alpn_list;
	getdns_dict *dict;
	struct sockaddr_in *sin4p;
	struct sockaddr_in6 *sin6p;
	getdns_eventloop *eventloop;
	getdns_transport_list_t transports[3];
	getdns_bindata bindata;
	struct sort_help sort_help[MAX_PROXY_CONTROL_OPTS];

	r = getdns_context_get_eventloop(down_context, &eventloop);
	if (r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "setup_upstream: unable to get eventloop\n");
		abort();
	}

	fprintf(stderr, "setup_upstream: starting, opts_count %d\n",
		usp->opts_count);

	usp->dns_error= 0;
	for (u= 0, po= usp->opts; u<usp->opts_count; u++, po++)
	{
		fprintf(stderr, "setup_upstream: opt %d\n", u);

		/* First set flags for individual protocols, we
		 * need them later
		 */
		DD_flag= !!(po->flags1 & PROXY_CONTROL_FLAG1_DD);
		A53_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_A53);
		D53_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_D53);
		AT_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_AT);
		DT_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_DT);
		AH2_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_AH2);
		DH2_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_DH2);
		AH3_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_AH3);
		DH3_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_DH3);
		AQ_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_AQ);
		DQ_flag= !!(po->flags2 & PROXY_CONTROL_FLAG2_DQ);

		/* Reject if both Ax and Dx are set */
		if ( (A53_flag && D53_flag) ||
			(AT_flag && DT_flag) ||
			(AH2_flag && DH2_flag) ||
			(AH3_flag && DH3_flag) ||
			(AQ_flag && DQ_flag))
		{
			fprintf(stderr, "setup_upstream: Ax and Dx\n");
			usp->dns_error= BADPROXYPOLICY;
fprintf(stderr, "%s, %d\n", __FILE__, __LINE__);
			goto error;
		}

		/* Compute what protocols we can use. Currently we support
		 * only Do53, DoT, and DoH2
		 */
		if (DD_flag)
		{
			/* Support only protocols that are explictly
			 * enabled.
			 */
			do_Do53 = A53_flag;
			do_DoT = AT_flag;
			do_DoH2 = AH2_flag;
		}
		else
		{
			/* Support all protocols expect those explictly
			 * disabled.
			 */
			do_Do53 = D53_flag ? 0 : 1;
			do_DoT = DT_flag ? 0 : 1;
			do_DoH2 = DH2_flag ? 0 : 1;
		}

		po->target = 0;
		po->status = TS_NOT_STARTED;

		/* Check U, UA, and A flags */
		U_flag= !!(po->flags1 & PROXY_CONTROL_FLAG1_U);
		UA_flag= !!(po->flags1 & PROXY_CONTROL_FLAG1_UA);
		A_flag= !!(po->flags1 & PROXY_CONTROL_FLAG1_A);
		if (U_flag + UA_flag + A_flag > 1)
		{
			fprintf(stderr,
				"setup_upstream: too many of U, UA, A\n");
			usp->dns_error= BADPROXYPOLICY;
fprintf(stderr, "%s, %d\n", __FILE__, __LINE__);
			goto error;
		}
		if (U_flag + UA_flag + A_flag == 0)
		{
			/* No preference. Select GETDNS_TRANSPORT_TLS 
			 * followed by GETDNS_TRANSPORT_UDP and
			 *  GETDNS_TRANSPORT_TCP
			 */
			i = 0;
			if (do_DoT || do_DoH2)
				transports[i++] = GETDNS_TRANSPORT_TLS;
			if (do_Do53)
			{
				transports[i++] = GETDNS_TRANSPORT_UDP;
				transports[i++] = GETDNS_TRANSPORT_TCP;
			}
			transports_count = i;

			po->target = TS_OPPORTUNISTIC;
		}
		else if (U_flag)
		{
			/* Only unencrypted. Select GETDNS_TRANSPORT_UDP
			 * followed by GETDNS_TRANSPORT_TCP
			 */
			i = 0;
			if (do_Do53)
			{
				transports[i++] = GETDNS_TRANSPORT_UDP;
				transports[i++] = GETDNS_TRANSPORT_TCP;
			}
			transports_count = i;

			po->target = TS_UNENCRYPTED;
		}
		else if (UA_flag)
		{
			/* Only unauthenticated. Select GETDNS_TRANSPORT_TLS
			 */
			i = 0;
			if (do_DoT || do_DoH2)
				transports[i++] = GETDNS_TRANSPORT_TLS;
			transports_count = i;

			po->target = TS_UNAUTHENTICATED;
		}
		else if (A_flag)
		{
			i = 0;
			if (do_DoT || do_DoH2)
				transports[i++] = GETDNS_TRANSPORT_TLS;
			transports_count = i;

			po->target = TS_AUTHENTICATED;
		}
		else
		{
			fprintf(stderr, "setup_upstream: weird state\n");
			abort();
		}

		if (transports_count == 0)
		{
			fprintf(stderr,
				"setup_upstream: no matching transports\n");
			usp->dns_error= BADPROXYPOLICY;
fprintf(stderr, "%s, %d\n", __FILE__, __LINE__);
			goto error;
		}

		/* P and D flags can only be set if the A flag is set. */
		P_flag= !!(po->flags1 & PROXY_CONTROL_FLAG1_P);
		D_flag= !!(po->flags1 & PROXY_CONTROL_FLAG1_D);
fprintf(stderr, "setup_upstream: flags1 0x%x, P_flag %d, D_flag %d\n", po->flags1, P_flag, D_flag);
		if ((P_flag || D_flag) && !A_flag)
		{
			fprintf(stderr, "setup_upstream: P or D but not A\n");
			usp->dns_error= BADPROXYPOLICY;
fprintf(stderr, "%s, %d\n", __FILE__, __LINE__);
			goto error;
		}

		if (po->infname)
		{
			/* Currently we can't support selection of
			 * outgoing interfaces.
			 */
			fprintf(stderr, "setup_upstream: interface name not supported yet\n");
			usp->dns_error= BADPROXYPOLICY;
fprintf(stderr, "%s, %d\n", __FILE__, __LINE__);
			goto error;
		}

		if ((r = getdns_context_create(&up_context, 1 /*set_from_os*/))
			!= GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
			"setup_upstream: getdns_context_create failed\n");
			abort();
		}
		fprintf(stderr, "setup_upstream: context %p\n",
			(void *)up_context);
		r = getdns_context_set_eventloop(up_context, eventloop);
		if (r != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
				"setup_upstream: unable to set eventloop\n");
			abort();
		}
		r = getdns_context_set_resolution_type(up_context,
			GETDNS_RESOLUTION_STUB);
		if (r != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
	"setup_upstream: getdns_context_set_resolution_type failed\n");
			abort();
		}
		if (A_flag)
		{
			r = getdns_context_set_tls_authentication(up_context,
				GETDNS_AUTHENTICATION_REQUIRED);
			if (r != GETDNS_RETURN_GOOD)
			{
				fprintf(stderr,
	"setup_upstream: getdns_context_set_tls_authentication failed\n");
				abort();
			}
		}
		po->context = up_context;
		po->ready = 1;
		po->dane_request_id = 0;
		po->incoming_requests = NULL;

		if ((r = getdns_context_set_dns_transport_list(up_context,
			transports_count, transports)) != GETDNS_RETURN_GOOD)

		{
			fprintf(stderr,
				"setup_upstream: cannot set transports\n");
			abort();
		}

		fprintf(stderr, "setup_upstream: addr_count %d\n",
			po->addr_count);
		if (po->addr_count)
		{
			list = getdns_list_create();
			for (i= 0; i<po->addr_count; i++)
			{
				dict = getdns_dict_create();
				switch(po->addrs[i].ss_family)
				{
				case AF_INET:
					sin4p= (struct sockaddr_in *)
						&po->addrs[i];
					bindata.data = (uint8_t *)"IPv4";
					bindata.size = strlen((char *)
						bindata.data);
					getdns_dict_set_bindata(dict,
						"address_type", &bindata);
					bindata.data = (uint8_t *)
						&sin4p->sin_addr;
					bindata.size = sizeof(sin4p->sin_addr);
					getdns_dict_set_bindata(dict,
						"address_data", &bindata);
					break;
				case AF_INET6:
					sin6p= (struct sockaddr_in6 *)
						&po->addrs[i];
					bindata.data = (uint8_t *)"IPv6";
					bindata.size = strlen((char *)
						bindata.data);
					getdns_dict_set_bindata(dict,
						"address_type", &bindata);
					bindata.data = (uint8_t *)
						&sin6p->sin6_addr;
					bindata.size = sizeof(sin6p->sin6_addr);
					getdns_dict_set_bindata(dict,
						"address_data", &bindata);
					break;
				default:
					fprintf(stderr,
				"setup_upstream: unknown address family\n");
					abort();
				}
				if (po->name)
				{
					bindata.data = (uint8_t *)po->name;
					bindata.size = strlen((char *)
						bindata.data);
					getdns_dict_set_bindata(dict,
						"tls_auth_name", &bindata);
				}
				if (po->alpn_count)
				{
					alpn_list = getdns_list_create();
					for (j = 0; j<po->alpn_count; j++)
					{
						bindata.data =
							(unsigned char *)
							po->alpn[j];
						bindata.size =
							strlen(po->alpn[j]);
						getdns_list_set_bindata(
							alpn_list, j,
						&bindata);
					}
					getdns_dict_set_list(dict, "alpn",
						alpn_list);
				}
				if (po->port)
				{
					getdns_dict_set_int(dict, "port",
						po->port);
					getdns_dict_set_int(dict, "tls_port",
						po->port);
				}
				getdns_list_set_dict(list, i, dict);
			}
			fprintf(stderr, "setup_upstream: addr list %s\n",
				getdns_pretty_print_list(list));
			if ((r = getdns_context_set_upstream_recursive_servers(
				up_context, list)) != GETDNS_RETURN_GOOD)

			{
				fprintf(stderr,
			"setup_upstream: cannot set upstream list: %d\n",
					r);
				abort();
			}
		}
		if (A_flag && D_flag) {
			/* get DANE records first */
			static getdns_dict *dnssec = NULL;
			char qname[1025] = "_853._tcp.";

			qname[1024] = 0;
			strncat(qname, po->name, sizeof(qname)
			                       - sizeof("_853._tcp.") - 1);

			fprintf(stderr, "setup_upstream: lookup DANE records "
					"for %s before this upstream is ready"
					"\n", qname);

			if (!dnssec && (r = getdns_str2dict(
			    "{dnssec_return_all_statuses:"
			    "GETDNS_EXTENSION_TRUE}", &dnssec)))
				stubby_error("Could make dnssec extension "
				    "dict: %s", stubby_getdns_strerror(r));
	
			if ((r = getdns_general(down_context, qname,
			    GETDNS_RRTYPE_TLSA, dnssec, po,
			    &po->dane_request_id, dane_request_cb)))
				stubby_error("Could not schedule dane "
				    "query: %s", stubby_getdns_strerror(r));
	 
			po->ready = 0;
		}

		sort_help[u].usp = usp;
		sort_help[u].index = u;
	}

	/* Create sorted */
	qsort(sort_help, usp->opts_count, sizeof(sort_help[0]), opt_cmp);

	for (u= 0; u<usp->opts_count; u++)
	{
		usp->sorted[u] = sort_help[u].index;

		fprintf(stderr, "setup_upstream: sorted %d -> %d\n",
			u, usp->sorted[u]);
	}

	return;
error:
	fprintf(stderr,
		"setup_upstream: error, should clear getdns contexts\n");
}

static int opt_cmp(const void *v1, const void *v2)
{
	int ip1, ip2;
	const struct sort_help *e1, *e2;
	const struct proxy_opt *p1, *p2;
	
	e1= v1;
	e2= v2;

	fprintf(stderr, "opt_cmp: e1 index %d, e2 index %d\n",
		e1->index, e2->index);

	p1= &e1->usp->opts[e1->index];
	p2= &e2->usp->opts[e2->index];

	if (p1->target > p2->target)
		return -1;
	if (p1->target < p2->target)
		return 1;

	/* Authentication options are the same. Prefer IPv6. Assume that each
	 * option has one type of addresses.
	 */
	ip1 = 0;	/* No addresses */
	ip2 = 0;
	if (p1->addr_count != 0)
	{
		if (p1->addrs[0].ss_family == AF_INET6)
			ip1 = -1;
		else
			ip1 = 1;
	}
	if (p2->addr_count != 0)
	{
		if (p2->addrs[0].ss_family == AF_INET6)
			ip2 = -1;
		else
			ip2 = 1;
	}

	if (ip1 > ip2)
		return -1;
	if (ip2 > ip1)
		return 1;
	return 0;
}

static int select_upstream(struct upstream *usp)
{
	int Xbest_completed, Xbest_potential;
	unsigned u, best_completed_status, best_potential_target;
	int s;
	struct proxy_opt *op;

	/* Select an uptream to try next */
	Xbest_completed = -1;
	best_completed_status = 0;
	Xbest_potential = -1;
	best_potential_target = 0;
	
	for (u= 0; u<usp->opts_count; u++)
	{
		s = usp->sorted[u];
		op = &usp->opts[s];

		fprintf(stderr, "select_upstream: u %d, s %d\n", u, s);

		if (op->status != TS_NOT_STARTED)
		{
			if (Xbest_completed == -1)
			{
				Xbest_completed = s;
				best_completed_status = op->status;
			}
			else if (op->status > best_completed_status)
			{
				Xbest_completed = s;
				best_completed_status = op->status;
			}
		}
		else
		{
			if (Xbest_potential == -1)
			{
				Xbest_potential = s;
				best_potential_target = op->target;
			}
			else if (op->target > best_potential_target)
			{
				Xbest_potential = s;
				best_potential_target = op->target;
			}
		}
	}

	if (Xbest_completed == -1 && Xbest_potential == -1)
	{
		fprintf(stderr, "select_upstream: no upstream?\n");
		abort();
	}
	if (Xbest_completed == -1)
		return Xbest_potential;
	if (Xbest_potential == -1)
		return Xbest_completed;

	if (best_potential_target > best_completed_status)
		return Xbest_potential;
	else
		return Xbest_completed;
}

#define POLICY_N_ADDR		3
#define POLICY_N_SVCPARAMS	8

static void proxy_policy2opt(getdns_proxy_policy *policy, int do_ipv6,
	uint8_t *buf, size_t *sizep);

static void response_add_proxy_option(getdns_dict *response, uint8_t *buf,
	size_t bufsize)
{
	unsigned u;
	uint32_t transport, type;
	size_t add_list_len, options_len;
	getdns_bindata *bindatap;
	getdns_list *add_list, *opt_list;
	getdns_dict *rr_dict, *proxy_rr;
	struct sockaddr_in *sin4p;
	struct sockaddr_in6 *sin6p;
	getdns_proxy_policy policy;
	getdns_bindata bindata;

	fprintf(stderr, "response_add_proxy_option(start): response %s\n",
		getdns_pretty_print_dict(response));

	if (getdns_dict_get_int(response, "/call_reporting/0/transport",
		&transport) != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
	"reponse_add_proxy_option: can't get /call_reporting/0/transport\n");
		return;
	}
	policy.flags1 = 0;
	policy.flags2 = 0;
	switch(transport)
	{
	case GETDNS_TRANSPORT_UDP:
	case GETDNS_TRANSPORT_TCP:
		policy.flags1 |= PROXY_CONTROL_FLAG1_U;
		policy.flags2 |= PROXY_CONTROL_FLAG2_A53;
		break;
		
	case GETDNS_TRANSPORT_TLS:
		policy.flags2 |= PROXY_CONTROL_FLAG2_AT;

		if (getdns_dict_get_bindata(response,
			"/call_reporting/0/tls_auth_status",
			&bindatap) != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"reponse_add_proxy_option: can't get "
		"/call_reporting/0/tls_auth_status\n");
			return;
		}

		if (bindatap->size == 4 &&
			memcmp(bindatap->data, "None", 4) == 0)
		{
			/* No authentication */
			policy.flags1 |= PROXY_CONTROL_FLAG1_UA;
		}
		else if (bindatap->size == 6 &&
			memcmp(bindatap->data, "Failed", 6) == 0)
		{
			/* Authentication failed */
			policy.flags1 |= PROXY_CONTROL_FLAG1_UA;

			/* We should check if authentication was required */
		}
		else if (bindatap->size == 7 &&
			memcmp(bindatap->data, "Success", 7) == 0)
		{
			/* Authentication succeeded */
			policy.flags1 |= PROXY_CONTROL_FLAG1_A;
		}
		else
		{

			fprintf(stderr,
	"reponse_add_proxy_option: unknown tls_auth_status '%.*s'\n",
				(int)bindatap->size, bindatap->data);
			abort();
		}
		break;

	default:
		fprintf(stderr,
			"reponse_add_proxy_option: unknown transport %d\n",
			transport);
		abort();
	}

	policy.flags1 |= PROXY_CONTROL_FLAG1_DD;

	if (getdns_dict_get_bindata(response,
		"/call_reporting/0/query_to/address_type", &bindatap) !=
		GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
	"reponse_add_proxy_option: can't get query_to/address_type\n");
		return;
	}
	if (bindatap->size == 4 && memcmp(bindatap->data, "IPv4", 4) == 0)
	{
fprintf(stderr, "reponse_add_proxy_option: IPv4 address\n");
		if (getdns_dict_get_bindata(response,
			"/call_reporting/0/query_to/address_data",
			&bindatap) != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"reponse_add_proxy_option: can't get query_to/address_data\n");
			return;
		}
		sin4p= (struct sockaddr_in *)&policy.addrs[0];
		sin4p->sin_family = AF_INET;
		memcpy(&sin4p->sin_addr, bindatap->data,
			sizeof(sin4p->sin_addr));
		policy.addr_count = 1;
	}
	else if (bindatap->size == 4 && memcmp(bindatap->data, "IPv6", 4) == 0)
	{
fprintf(stderr, "reponse_add_proxy_option: IPv6 address\n");
		if (getdns_dict_get_bindata(response,
			"/call_reporting/0/query_to/address_data",
			&bindatap) != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"reponse_add_proxy_option: can't get query_to/address_data\n");
			return;
		}
		sin6p= (struct sockaddr_in6 *)&policy.addrs[0];
		sin6p->sin6_family = AF_INET6;
		memcpy(&sin6p->sin6_addr, bindatap->data,
			sizeof(sin6p->sin6_addr));
		policy.addr_count = 1;
	}
	else
	{
		fprintf(stderr,
		"reponse_add_proxy_option: unknown address type %.*s\n",
			(int)bindatap->size, bindatap->data);
		abort();
	}

	policy.domainname = NULL;
	policy.svcparams[0].key = NULL;
	policy.interface = NULL;

	proxy_policy2opt(&policy, policy.addrs[0].ss_family == AF_INET6,
		buf, &bufsize);
	fprintf(stderr, "reponse_add_proxy_option: size %lu\n", bufsize);
	fprintf(stderr, "reponse_add_proxy_option: buf");
	for (u = 0; u<bufsize; u++)
		fprintf(stderr, " %02x", buf[u]);
	fprintf(stderr, "\n");

	if (getdns_dict_get_list(response, "/replies_tree/0/additional",
		&add_list) != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "reponse_add_proxy_option: add additional\n");
		abort();
	}
	if (getdns_list_get_length(add_list, &add_list_len) !=
		GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"reponse_add_proxy_option: failed to get length of list\n");
		abort();
	}
	for (u = 0; u<add_list_len; u++)
	{
		if (getdns_list_get_dict(add_list, u, &rr_dict) !=
			GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"reponse_add_proxy_option: failed to get list item %d\n",
				u);
			abort();
		}
		if (getdns_dict_get_int(rr_dict, "type", &type) !=
			GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
			"reponse_add_proxy_option: failed to get type\n");
			abort();
		}
		if (type == GETDNS_RRTYPE_OPT)
			break;
	}
	if (u >= add_list_len)
	{
		rr_dict = getdns_dict_create();
		getdns_dict_set_int(rr_dict, "do", 0);
		getdns_dict_set_int(rr_dict, "extended_rcode", 0);
		getdns_dict_set_int(rr_dict, "type", GETDNS_RRTYPE_OPT);
		getdns_dict_set_int(rr_dict, "udp_payload_size", 512);
		getdns_dict_set_int(rr_dict, "version", 0);
		getdns_dict_set_int(rr_dict, "z", 0);
		getdns_list_set_dict(add_list, u, rr_dict);
		if (getdns_list_get_dict(add_list, u, &rr_dict) !=
			GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"reponse_add_proxy_option: failed to get list item %d\n",
				u);
			abort();
		}
	}
	getdns_dict_remove_name(rr_dict, "/rdata/rdata_raw");
	if (getdns_dict_get_list(rr_dict, "/rdata/options", &opt_list) !=
		GETDNS_RETURN_GOOD)
	{
		opt_list = getdns_list_create();
		getdns_dict_set_list(rr_dict, "/rdata/options", opt_list);
		getdns_dict_get_list(rr_dict, "/rdata/options", &opt_list);
	}
	if (getdns_list_get_length(opt_list, &options_len) !=
		GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"reponse_add_proxy_option: can't get length for options\n");
		abort();
	}
	proxy_rr = getdns_dict_create();
	getdns_dict_set_int(proxy_rr, "option_code", GLDNS_EDNS_PROXY_CONTROL);
	bindata.data = buf;
	bindata.size = bufsize;
	getdns_dict_set_bindata(proxy_rr, "option_data", &bindata);
	getdns_list_set_dict(opt_list, options_len, proxy_rr);

	fprintf(stderr, "reponse_add_proxy_option(end): result dict: %s\n",
		getdns_pretty_print_dict(response));
}

#include <stddef.h>

#define SVC_KEY_ALPN	1

/* Note: this table must be kept sort based on 'value' */
static struct
{
	uint16_t value;
	char *key;
} svckeys[] = 
{
	{ SVC_KEY_ALPN, "alpn" },	/* 1 */
	{ 0, NULL }
};

/* Copied from getdns/src/context.c. This needs to be a library function */
static void proxy_policy2opt(getdns_proxy_policy *policy, int do_ipv6,
	uint8_t *buf, size_t *sizep)
{
	uint8_t inflen;
	uint16_t key16, len16;
	int i, j, addr_count;
	ptrdiff_t len, totlen;
	size_t datalen;
	char *l, *dot, *key, *v, *vp, *comma;
	uint8_t *bp, *addr_type, *addr_len, *addrp, *domainlenp,
		*domainp, *svclenp, *svcp, *inflenp, *infp, *lastp, *endp,
		*datap, *wire_keyp, *wire_lenp, *wire_datap;
	uint16_t *flags1p, *flags2p;
	struct sockaddr_in *sin4p;
	struct sockaddr_in6 *sin6p;
	uint8_t wirebuf[256];

	endp= buf + *sizep;

	flags1p= (uint16_t *)buf;
	flags2p= &flags1p[1];

	addr_type= (uint8_t *)&flags2p[1];
	addr_len= &addr_type[1];

	*flags1p= htons(policy->flags1);
	*flags2p= htons(policy->flags2);

fprintf(stderr, "proxy_policy2opt: flag1 0x%x, flags2 0x%x\n",
	ntohs(*flags1p), ntohs(*flags2p));

	/* Count the number of addresses to include */
	addr_count= 0;
	for (i= 0; i<policy->addr_count; i++)
	{
		if (!do_ipv6 && policy->addrs[i].ss_family == AF_INET)
			addr_count++;
		if (do_ipv6 && policy->addrs[i].ss_family == AF_INET6)
			addr_count++;
	}

	if (addr_count)
	{
		if (do_ipv6)
		{
			*addr_type = 2;
			*addr_len = addr_count * sizeof(struct in6_addr);
			addrp= &addr_len[1];
			if (endp - addrp < *addr_len)
			{
				fprintf(stderr,
				"proxy_policy2opt: not enogh space\n");
				abort();
			}
			for (i= 0; i<policy->addr_count; i++)
			{
				if (policy->addrs[i].ss_family != AF_INET6)
					continue;
				sin6p = (struct sockaddr_in6 *)
					&policy->addrs[i];
				memcpy(addrp, &sin6p->sin6_addr, 
					sizeof(sin6p->sin6_addr));
				addrp += sizeof(sin6p->sin6_addr);
			}
		}
		else
		{
			*addr_type = 1;
			*addr_len = addr_count * sizeof(struct in_addr);
			addrp= &addr_len[1];
			if (endp - addrp < *addr_len)
			{
				fprintf(stderr,
				"proxy_policy2opt: not enogh space\n");
				abort();
			}
			for (i= 0; i<policy->addr_count; i++)
			{
				if (policy->addrs[i].ss_family != AF_INET)
					continue;
				sin4p = (struct sockaddr_in *)
					&policy->addrs[i];
				memcpy(addrp, &sin4p->sin_addr, 
					sizeof(sin4p->sin_addr));
				addrp += sizeof(sin4p->sin_addr);
			}
		}
		assert (addrp - &addr_len[1] == *addr_len);
		domainlenp= addrp;
	}
	else 
	{
		*addr_type = 0;
		*addr_len = 0;
		domainlenp= &addr_len[1];
	}

	if (endp - domainlenp < 1)
	{
		fprintf(stderr,
		"proxy_policy2opt: not enough space\n");
		abort();
	}
	*domainlenp = 0;
	domainp= &domainlenp[1];
	if (policy->domainname)
	{
		l= policy->domainname;
		while(l)
		{
			dot= strchr(l, '.');
			if (dot)
				len= dot-l;
			else
				len= strlen(l);
			if (len > 63)
			{
				fprintf(stderr,
					"proxy_policy2opt: bad label length\n");
				abort();
			}
			if (endp - domainlenp < 1)
			{
				fprintf(stderr,
				"proxy_policy2opt: not enough space\n");
				abort();
			}
			*domainp= len;
			domainp++;
			if (endp - domainlenp < len)
			{
				fprintf(stderr,
				"proxy_policy2opt: not enough space\n");
				abort();
			}
			memcpy(domainp, l, len);
			domainp += len;

			if (!dot)
				break;
			l= dot+1;
			if (l[0] == '\0')
				break;
		}

		/* Add trailing label */
		if (endp - domainlenp < 1)
		{
			fprintf(stderr, "proxy_policy2opt: not enough space\n");
			abort();
		}
		*domainp= 0;
		domainp++;

		*domainlenp = domainp - &domainlenp[1];
	}

	svclenp = domainp;
	if (endp - svclenp < 1)
	{
		fprintf(stderr,
		"proxy_policy2opt: not enough space\n");
		abort();
	}
	*svclenp = 0;
	svcp = &svclenp[1];
	if (policy->svcparams[0].key != NULL)
	{
		for (i = 0; svckeys[i].key != NULL; i++)
		{
			key = svckeys[i].key;
			for (j = 0; j<POLICY_N_SVCPARAMS; j++)
			{
				if (policy->svcparams[j].key == NULL)
					break;
				if (strcmp(key, policy->svcparams[j].key) == 0)
					break;
			}
			if (j >= POLICY_N_SVCPARAMS ||
				policy->svcparams[j].key == NULL)
			{
				/* Key not needed */
				continue;
			}

			switch(svckeys[i].value)
			{
			case SVC_KEY_ALPN:
				v = policy->svcparams[j].value;
				if (v == NULL)
				{
					fprintf(stderr,
				"proxy_policy2opt: value expected for alpn\n");
					abort();
				}
				if (strlen(v) + 1 > sizeof(wirebuf))
				{
					fprintf(stderr,
				"proxy_policy2opt: alpn list too long\n");
					abort();
				}
				vp= v;
				bp= wirebuf;
				while (vp)
				{
					comma = strchr(vp, ',');
					if (comma)
					{
						len = comma - vp;
						*bp = len;
						bp++;
						memcpy(bp, vp, len);
						bp += len;
						vp = comma + 1;
						continue;
					}
					len = strlen(vp);
					*bp = len;
					bp++;
					memcpy(bp, vp, len);
					bp += len;
					break;;
				}
				datap = wirebuf;
				datalen = bp-wirebuf;
				break;

			default:
				fprintf(stderr,
				"proxy_policy2opt: unknown svc key value\n");
				abort();
			}

			totlen = 4 + datalen;
			if (endp - svcp < totlen)
			{
				fprintf(stderr,
				"proxy_policy2opt: not enough space\n");
				abort();
			}
			wire_keyp = svcp;
			wire_lenp = &wire_keyp[2];
			wire_datap = &wire_lenp[2];

			key16 = htons(svckeys[i].value);
			memcpy(wire_keyp, &key16, 2);
			len16 = htons(datalen);
			memcpy(wire_lenp, &len16, 2);
			if (datalen)
				memcpy(wire_datap, datap, datalen);
			svcp = wire_datap + datalen;
		}
	}
	len = svcp - &svclenp[1];
	if (len > 255)
	{
		fprintf(stderr, "svc too large\n");
		abort();
	}
	*svclenp = len;

	inflenp = svcp;
	if (endp - inflenp < 1)
	{
		fprintf(stderr,
		"proxy_policy2opt: not enough space\n");
		abort();
	}

	inflen = 0;
	if (policy->interface)
	{
		inflen= strlen(policy->interface);
	}
	*inflenp = inflen;
	infp= &inflenp[1];
	if (inflen)
	{
		if (endp - infp < inflen)
		{
			fprintf(stderr,
			"proxy_policy2opt: not enough space\n");
			abort();
		}
		memcpy(infp, policy->interface, inflen);
	}
fprintf(stderr, "inflen %d, interface %s\n", inflen, policy->interface);

	lastp = &infp[inflen];

	*sizep= lastp - buf;
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
