#ifndef SERVER_H
#define SERVER_H

#include <getdns/getdns.h>

int server_listen(getdns_context *context, int validate_dnssec);

#endif
