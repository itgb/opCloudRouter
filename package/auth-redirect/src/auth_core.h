#ifndef _AUTH_CORE_H_
#define _AUTH_CORE_H_

#include "auth_comm.h"
#include "auth_config.h"
#include "auth_ioc.h"

enum AUTH_STATUS {
	AUTH_STATUS_RUN		= 0,
	AUTH_STATUS_STOP	= 1,
};

/*global info of auth moudle*/
struct auth_global {
	struct list_head rule_list;
	spinlock_t lock; 
	struct auth_options auth_option;
	struct list_head if_list;
	enum AUTH_STATUS status;
};

// int update_auth_rules(struct auth_ip_rule *ip_rules, uint32_t n_rule);
// int update_auth_options(struct auth_options *options);
int	get_auth_status(void);
int auth_disable(void);
int auth_enable(void);
// void display_auth_ip_rule(struct auth_ip_rule *ip_rule);
// void display_auth_ip_rules(void);
// int clean_auth_rules(void);
// int add_auth_rule(struct auth_ip_rule_node *ip_rule_node);
// int copy_auth_ip_rule_to_node(struct auth_ip_rule_node *rule_node, struct auth_ip_rule *ip_rule);

// int set_auth_options(struct auth_options *options);

// void display_auth_if_infos(void);
// int clean_auth_if_infos(void);
// int add_auth_if_info(struct if_info_node *if_info_node);
// int copy_auth_if_info_to_node(struct if_info_node *if_info_node, struct auth_if_info *if_info);

#endif