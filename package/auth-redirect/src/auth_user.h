#ifndef _AUTH_USER_H_
#define _AUTH_USER_H_

#include "auth_ioc.h"
#include "auth_comm.h"

#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
 ((unsigned char *)&addr)[0], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[3]


struct user_node {
	struct hlist_node user_node;
	struct user_info info;
};

/*for avoid warning, delcare*/
struct user_node;
struct user_info;

int auth_user_init(void);
int auth_user_fini(void);
struct  user_node *auth_user_get(const unsigned char *mac);
struct user_node *auth_user_add(struct user_info *user_info);

int watchdog_tm_update(uint32_t msecs_intval);
int auth_user_status(struct user_node *user);
void display_all_user(void);
void display_user(struct user_node *user);

int update_auth_user_auth_type(struct user_node *user, int type);
int get_auth_user_auth_type(struct user_node *user);
int update_auth_user_status(struct user_node *user, int status);
int update_auth_user_ipv4(struct user_node *user, uint32_t ipv4);
uint32_t get_auth_user_ipv4(struct user_node *user);
int update_auth_users_stat(struct user_info *infos, uint16_t nc_user);
int update_auth_user_active_tm(struct user_node *user);
int kick_off_all_auth_auto_users(void);
int auth_users_get(struct user_stat_assist *assist);
#endif


