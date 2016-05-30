#ifndef _AUTH_CONFIG_H_
#define _AUTH_CONFIG_H_
#include "auth_ioc.h"

int do_set_auth_options(struct auth_ioc_arg *arg);
int do_set_auth_rules(struct auth_ioc_arg *arg);
int do_set_auth_user_stat(struct auth_ioc_arg *arg);
int do_get_auth_user_stat(struct auth_ioc_arg *arg);
int do_set_auth_ifinfo(struct auth_ioc_arg *arg);
int do_set_auth_urlinfo(struct auth_ioc_arg *arg);
int do_set_debug_options(struct auth_ioc_arg *arg);
#endif