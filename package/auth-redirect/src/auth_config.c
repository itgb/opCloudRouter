#include "auth_comm.h"
#include "auth_config.h"
#include "auth_ioc.h"
#include "auth_user.h"
#include "auth_rule.h"


static int auth_io_arg_check(struct auth_ioc_arg* arg, enum ARG_TYPE_E arg_type)
{
	char arg_type_strs[ARG_TYPE_NUM][ARG_TYPE_STR_LEN] = 
			{ {"AUTH_RULE"}, {"AUTH_OPTION"}, {"USER_GSTAT"},  
			  {"USER_SSTAT"}, {"NET_IF_INFO"}, {"BYPASS_URL_INFO"},
			  {"INVALID_ARG_TYPE"}
			};
	uint16_t len = 0, unit_len = 0;
	if (arg->type != arg_type) {
		arg_type = INVALID_ARG_TYPE;
		goto INVALID;
	}

	switch (arg_type) {
		case AUTH_RULE: 
		{	/*arg->num == 0 means cleaning rule*/
			unit_len = sizeof(struct auth_ip_rule);
			//break;
			/*todo:special check*/
			return 0;	/*AUTH_RULE Passing check directly*/
		}

		case AUTH_OPTION:
		{
			if (arg->num != 1) {
				goto INVALID;
			}
			unit_len = sizeof(struct auth_options);
			break;
		}

		case USER_GSTAT:
		{	/*head+body*/
			if (arg->num != 1) {
				goto INVALID;
			}
			unit_len = sizeof(struct user_stat_assist);
			break;
		}

		case USER_SSTAT:
		{	/*head+body*/
			if (arg->num == 0) {
				goto INVALID;
			}
			unit_len = sizeof(struct user_info);
			break;
		}

		case NET_IF_INFO:
		{	/*head + body, arg->nmu == 0 means cleaning if info*/
			unit_len = sizeof(struct auth_if_info);
			break;
		}

		case BYPASS_URL_INFO:
		{	/*head + body, arg->nmu == 0 means cleaning if info*/
			unit_len = sizeof(struct auth_url_info);
			break;
		}

		default:
		{
			unit_len = 0;
			arg_type = INVALID_ARG_TYPE;
			goto INVALID;
		}
	}
	len = arg->num * unit_len;
	if (len == arg->data_len) {
		return 0;
	}
INVALID:
	AUTH_WARN("%s IOC_ARG INVALID.\n", arg_type_strs[arg_type]);
	return -1;
}


int do_set_auth_rules(struct auth_ioc_arg* arg)
{
	void *data = NULL;
	if (auth_io_arg_check(arg, AUTH_RULE) != 0) {
		return -1;
	}
	data = (void*)arg + sizeof(struct auth_ioc_arg);  
	return update_auth_rules((struct ioc_auth_ip_rule *)data, arg->num);
}


int do_set_auth_options(struct auth_ioc_arg *arg)
{
	void *data = NULL;
	if (auth_io_arg_check(arg, AUTH_OPTION) != 0) {
		return -1;
	}
	data = (void*)arg + sizeof(struct auth_ioc_arg);
	return update_auth_options((struct auth_options*)data);
}


int do_set_auth_user_stat(struct auth_ioc_arg* arg)
{
	void *data = NULL;
	if (auth_io_arg_check(arg, USER_SSTAT) != 0) {
		return -1;
	}
	data = (void*)arg + sizeof(struct auth_ioc_arg);
	return update_auth_users_stat((struct user_info*)data, arg->num);
}


int do_get_auth_user_stat(struct auth_ioc_arg* arg)
{
	void *data = NULL;
	if (auth_io_arg_check(arg, USER_GSTAT) != 0) {
		return -1;
	}

	data = (void*)arg + sizeof(struct auth_ioc_arg);
	return auth_users_get((struct user_stat_assist*)data);
}


int do_set_auth_ifinfo(struct auth_ioc_arg *arg)
{	
	void *data = NULL;

	if (auth_io_arg_check(arg, NET_IF_INFO) != 0) {
		return -1;
	}
	data = (void*)arg + sizeof(struct auth_ioc_arg);
	return update_auth_if_info((struct auth_if_info*)data, arg->num);
}


int do_set_auth_urlinfo(struct auth_ioc_arg *arg)
{	
	void *data = NULL;

	if (auth_io_arg_check(arg, BYPASS_URL_INFO) != 0) {
		return -1;
	}
	data = (void*)arg + sizeof(struct auth_ioc_arg);
	return update_auth_url_info((struct auth_url_info*)data, arg->num);
}

int do_set_debug_options(struct auth_ioc_arg *arg)
{	
	void *data = NULL;

	if (auth_io_arg_check(arg, NET_IF_INFO) != 0) {
		return -1;
	}
	data = (void*)arg + sizeof(struct auth_ioc_arg);
	return 0;
}