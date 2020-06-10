#include "config.h"

#include <errno.h>
#include <string.h>

#include <getdns/getdns_extra.h>

#include "util.h"

const char *stubby_getdns_strerror(getdns_return_t r)
{
        return r == GETDNS_RETURN_IO_ERROR ? strerror(errno)
                                           : getdns_get_errorstr_by_id(r);
}
