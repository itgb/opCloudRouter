/* Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */
#ifndef __NSS_CRYPTO_HLOS_H
#define __NSS_CRYPTO_HLOS_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38) && !defined(AUTOCONF_INCLUDED)
#include<linux/config.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <asm/scatterlist.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <asm/cmpxchg.h>
#include <linux/hrtimer.h>
#include <linux/slab.h>
#include <linux/llist.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>

#define nss_crypto_info(fmt, arg...)	printk(KERN_INFO "<NSS-CRYPTO>:" fmt, ## arg)
#define nss_crypto_err(fmt, arg...)	printk(KERN_ERR "<NSS-CRYPTO>:" fmt, ## arg)
#define nss_crypto_dbg(fmt, arg...)	printk(KERN_DEBUG fmt, ## arg)

#define nss_crypto_assert(expr)		BUG_ON(!(expr))

#endif /* __NSS_CRYPTO_HLOS_H */
