/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 25 Mar 2015 16:32:06 +0800
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include "http_url_parse.h"

int http_get_data_parse(const unsigned char *data, int data_len, struct url_info *url_info)
{
	const unsigned char *line_start = data;
	int line_len = 0;
	int i = 0;
	const unsigned char *_uri_start = NULL;
	const unsigned char *_host_start = NULL;
	int _uri_len = 0;
	int _host_len = 0;

#define HTTP_GET_LINE 0x1
#define HTTP_HOST_LINE 0x2
	unsigned long status = 0;

	for (i = 0; i < data_len; i++)
	{
		if (line_start[line_len] != '\n')
		{
			line_len ++;
			continue;
		}
		if (line_start[line_len - 1] == '\r')
			line_len --;

		if (line_len < 6/* GET / HTTP/1.1*/)
		{
			line_len = 0;
			line_start = data + i + 1;
			continue;
		}

		if (!(status & HTTP_GET_LINE) && strncasecmp(line_start, "GET ", 4) == 0)
		{
			if (line_len > 14 && strncasecmp(line_start + line_len - 9, " HTTP/x.x", 6) == 0)
			{
				_uri_len = line_len - 4 - 9;
				_uri_start = line_start + 4;
				status |= HTTP_GET_LINE;
			}
		}
		else if (!(status & HTTP_HOST_LINE) && strncasecmp(line_start, "Host: ", 6) == 0)
		{
			_host_len = line_len - 6;
			_host_start = line_start + 6;
			status |= HTTP_HOST_LINE;
		}

		if (status == (HTTP_GET_LINE|HTTP_HOST_LINE))
			break;

		line_len = 0;
		line_start = data + i + 1;
	}

	url_info->uri_len = 0;
	url_info->host_len = 0;

	if ((status & HTTP_GET_LINE) == HTTP_GET_LINE)
	{
		url_info->uri = _uri_start;
		url_info->uri_len = _uri_len;
	}

	if ((status & HTTP_HOST_LINE) == HTTP_HOST_LINE)
	{
		url_info->host = _host_start;
		url_info->host_len = _host_len;
	}
#undef HTTP_GET_LINE 
#undef HTTP_HOST_LINE 
	return 0;
}


int http_post_data_parse(const unsigned char *data, int data_len, struct url_info *url_info)
{
	const unsigned char *line_start = data;
	int line_len = 0;
	int i = 0;
	const unsigned char *_uri_start = NULL;
	const unsigned char *_host_start = NULL;
	int _uri_len = 0;
	int _host_len = 0;

#define HTTP_POST_LINE 0x1
#define HTTP_HOST_LINE 0x7
	unsigned long status = 0;

	for (i = 0; i < data_len; i++)
	{
		if (line_start[line_len] != '\n')
		{
			line_len ++;
			continue;
		}
		if (line_start[line_len - 1] == '\r')
			line_len --;

		if (line_len < 7/* POST / HTTP/1.1*/)
		{
			line_len = 0;
			line_start = data + i + 1;
			continue;
		}

		if (strncasecmp(line_start, "POST ", 5) == 0)
		{
			if (line_len > 15 && strncasecmp(line_start + line_len - 9, " HTTP/x.x", 6) == 0)
			{
				_uri_len = line_len - 5 - 9;
				_uri_start = line_start + 5;
				status |= HTTP_POST_LINE;
			}
		}
		
		if (strncasecmp(line_start, "Host: ", 6) == 0)
		{
			_host_len = line_len - 6;
			_host_start = line_start + 6;
			status |= HTTP_HOST_LINE;
		}

		if (status == (HTTP_POST_LINE|HTTP_HOST_LINE))
			break;

		line_len = 0;
		line_start = data + i + 1;
	}

	url_info->uri_len = 0;
	url_info->host_len = 0;

	if ((status & HTTP_POST_LINE) == HTTP_POST_LINE)
	{
		url_info->uri = _uri_start;
		url_info->uri_len = _uri_len;
	}

	if ((status & HTTP_HOST_LINE) == HTTP_HOST_LINE)
	{
		url_info->host = _host_start;
		url_info->host_len = _host_len;
	}
#undef HTTP_POST_LINE 
#undef HTTP_HOST_LINE 
	return 0;
}

