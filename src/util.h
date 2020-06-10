#ifndef UTIL_H
#define UTIL_H

#include <getdns/getdns.h>

#ifndef GETDNS_RETURN_IO_ERROR
#define GETDNS_RETURN_IO_ERROR ((getdns_return_t) 3000)
#endif

const char *stubby_getdns_strerror(getdns_return_t r);

#endif
