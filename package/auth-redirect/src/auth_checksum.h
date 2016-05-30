#ifndef __NOS_CSUM_H__
#define __NOS_CSUM_H__

#include <linux/types.h>

unsigned int nos_csum(const unsigned char *buffer, size_t len);

#ifdef __KERNEL__
#else	//__KERNEL__

/*
 * ¾Ö²¿Ð£ÑéºÍ¼ÆËã
 */
__wsum csum_partial(const void *buff, int len, __wsum wsum);

/*
 * use space ip fast csum.
 */
unsigned short ip_fast_csum(const void *iph, unsigned int ihl);

/*
 * ip·¢ËÍÐ£ÑéºÍ¼ÆËã.
 */
static inline void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

/*
 * tcp Ð£ÑéºÍ
 */
unsigned short tcp_v4_check(int len, unsigned int saddr, unsigned int daddr, unsigned int base);

#endif	//__KERNEL__

#endif