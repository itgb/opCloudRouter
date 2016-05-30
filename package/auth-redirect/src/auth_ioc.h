#ifndef _AUTH_IOCS_H_
#define _AUTH_IOCS_H_

#include "auth_comm.h"

#define SIOCSAUTHRULES		0x100	/*set auth rules*/
#define SIOCSAUTHOPTIONS	0x101	/*set auth options*/
#define SIOCSUSRSTAT		0x102	/*set usr status*/
#define SIOCGUSRSTAT		0x103	/*get usr status*/
#define SIOCSIFINFO			0x104	/*set network interface*/
#define SIOCSAUTHURLS       0X105   /*set bypass url*/
#define SIOCSDEBUGOPTIONS	0x106	/*set debug options*/

#define	REDIRECT_URL_MAX		256
#define REDIRECT_TITLE_MAX		128
#define IF_NAME_MAX				32	
#define BYPASS_URI_LEN 	64
#define BYPASS_HOST_LEN 64
#define ETH_ALEN				6

#define IP_RULE_TYPE_NUM	3
#define IP_RULE_TYPE_STR_LEN 8
enum IP_RULE_TYPE_E {
	NORMAL	= 0,
	WHITE	= 1,
	BLACK	= 2,
};

/*ipv4 range*/
// struct auth_ip_rule {
// 	uint8_t 	type;	/*normal, white, black*/
// 	uint8_t		priority;
// 	uint8_t 	enable;
// 	uint32_t	min;	/*min ip*/
// 	uint32_t 	max;	/*max ip*/
// };

#define AUTH_RULE_NAME_MAX		128		/*the max name size of rule*/
struct ip_range {
	uint32_t min;
	uint32_t max;
};

struct auth_ip_rule
{
	char		name[AUTH_RULE_NAME_MAX];
	uint32_t 	type;
	uint32_t	enable;
	uint32_t 	priority;
	uint32_t 	timeout;
	struct ip_range *ip_ranges;
	uint32_t 	nc_ip_range;
	uint8_t 	step;
};

struct ioc_auth_ip_rule {
	char		name[AUTH_RULE_NAME_MAX];
	uint32_t 	type;
	uint32_t	enable;
	uint32_t 	priority;
	uint32_t 	timeout;
	uint8_t 	step;
	uint32_t 	nc_ip_range;
	/*struct ip_range *ip_ranges*/
};

// struct auth_ip_rule_node {
// 	struct list_head rule_node;
// 	struct auth_ip_rule ip_rule;
// };


/*auth options*/
struct auth_options {
	uint32_t	user_check_intval;	/*unit: seconds*/
	char 		redirect_url[REDIRECT_URL_MAX];	
	char		redirect_title[REDIRECT_TITLE_MAX];
	uint32_t    bypass_enable;
};

enum ARG_TYPE_E {
	AUTH_RULE	= 0,
	AUTH_OPTION	= 1,
	USER_GSTAT	= 2,
	USER_SSTAT	= 3,
	NET_IF_INFO	= 4,
	BYPASS_URL_INFO = 5,
	/*add new type here*/
	INVALID_ARG_TYPE,
};
#define ARG_TYPE_NUM  (INVALID_ARG_TYPE + 1)
#define ARG_TYPE_STR_LEN 16


enum USER_STATUS {
	USER_OFFLINE = 0,
	USER_ONLINE = 1,
	/*new status add here*/
	INVALID_USER_STATUS,
};
#define USER_STATUS_NUM (INVALID_USER_STATUS + 1)
#define USER_STATUS_STR_LEN 16

#pragma pack(4)
struct user_info {
	uint32_t ipv4;
	uint32_t status;
	uint64_t jf;
	unsigned char mac[ETH_ALEN];
	uint16_t auth_type;
	//unsigned char reserved[2];
};


struct user_stat_assist {
	uint16_t more;		/*more user stat info*/
	uint16_t nc_element;/*num count of mem space which unit is sizeof(user_info)*/
	uint16_t nc_user;	/*real num of user*/
	uint16_t nc_unused; /*more user need to get*/
	uint64_t tm_stamp;
	unsigned long addr; /*user_space addr*/
};
/*"assit + user_info" kernel copy to user*/
#pragma pack()

#define NET_IF_TYPE_NUM	3
#define NET_IF_TYPE_STR_LEN 8
enum IF_TYPE_E {
	LAN_E	= 0,
	WAN_E	= 1,
	LOOP_E 	= 2,
};
#pragma pack(4)
/*interface info*/
struct auth_if_info {
	uint8_t 		type;
	unsigned char 	if_name[IF_NAME_MAX];
};

/*url info*/
struct auth_url_info {
	uint8_t 		action;
	uint8_t 		uri_len;
	uint8_t 		host_len;
	unsigned char 	uri[BYPASS_URI_LEN];	/*null terminated*/
	unsigned char 	host[BYPASS_HOST_LEN]; /*null terminated*/
	uint8_t			step;
};

/*ioctl cmd args*/
struct auth_ioc_arg {
	uint8_t		type;		/*element type, just for check*/
	uint16_t 	num;		/*element count*/
	uint16_t	data_len;	/*num * sizeof element*/
	/*element data body*/
};
#pragma pack()
#endif