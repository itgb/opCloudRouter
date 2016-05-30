#include "auth_checksum.h"


static inline unsigned short FROM32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static inline unsigned int do_csum(const unsigned char *buff, size_t len)
{
	int odd, count;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				count--;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (count);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = FROM32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

unsigned int nos_csum(const unsigned char *buff, size_t len)
{
	return ~do_csum(buff, len) & 0x0000ffff;
}

#ifdef __KERNEL__

#else //__KERNEL
unsigned int csum_partial(const void *buff, int len, unsigned int wsum)
{
	unsigned int sum = (unsigned int)wsum;
	unsigned int result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return (unsigned int)result;
}

unsigned short ip_fast_csum(const void *iph, unsigned int ihl)
{
	return ~do_csum(iph, ihl * 4);
}

static inline unsigned short csum_fold(unsigned int csum)
{
	uint32_t sum = (uint32_t)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (unsigned short)~sum;
}

struct pse_hdr_st {
	unsigned int saddr, daddr;
	unsigned char mbz, proto;
	unsigned short len;
};

unsigned short tcp_v4_check(int len, unsigned int saddr,
		unsigned int daddr, unsigned int base)
{
	struct pse_hdr_st psd;

	psd.saddr = saddr;
	psd.daddr = daddr;
	psd.mbz = 0;
	psd.proto = IPPROTO_TCP;
	psd.len = htons(len);

	return csum_fold(csum_partial(&psd, sizeof(psd), base));
}

#endif //KERNEL
