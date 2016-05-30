/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 25 Mar 2015 16:32:06 +0800
 */
#ifndef _HTTP_URL_PARSE_H_
#define _HTTP_URL_PARSE_H_

#include <linux/kernel.h>
#include <linux/string.h>

struct url_info {
	const unsigned char *uri;
	const unsigned char *host;
	int uri_len;
	int host_len;
};

extern int http_get_data_parse(const unsigned char *data, int data_len, struct url_info *url_info);
extern int http_post_data_parse(const unsigned char *data, int data_len, struct url_info *url_info);
static inline void dump_print(const unsigned char *data, int len)
{
	int i;

	printk("###>> ");
	for (i = 0; i < len; i++)
	{   
		printk("%c", data[i]);
	}   
	printk(" <<\n");
}


#endif /* _HTTP_URL_PARSE_H_ */
