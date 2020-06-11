#ifndef CONFIGFILE_H
#define CONFIGFILE_H

#include <getdns/getdns.h>

char *home_config_file(void);
char *system_config_file(void);

void init_config(getdns_context *context);
void delete_config(void);

int read_config(getdns_context *context, const char *custom_config_fn);

char *get_api_info(getdns_context *context);

const getdns_list *get_config_listen_list(void);

#endif
