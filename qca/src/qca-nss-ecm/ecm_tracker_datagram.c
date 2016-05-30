/*
 **************************************************************************
 * Copyright (c) 2014, The Linux Foundation.  All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/sysctl.h>
#include <linux/kthread.h>
#include <linux/sysdev.h>
#include <linux/fs.h>
#include <linux/pkt_sched.h>
#include <linux/string.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <asm/unaligned.h>
#include <asm/uaccess.h>	/* for put_user */
#include <net/ipv6.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_TRACKER_DATAGRAM_DEBUG_LEVEL

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_tracker_datagram.h"

/*
 * Magic numbers
 */
#define ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC 0x3AbC

/*
 * struct ecm_tracker_datagram_internal_instance
 */
struct ecm_tracker_datagram_internal_instance {
	struct ecm_tracker_datagram_instance datagram_base;	/* MUST BE FIRST FIELD */

	/*
	 * skb-next and skb->prev pointers are leveraged for these lists
	 */
	struct sk_buff *src_recvd_order;	/* sk buff list as sent by src */
	struct sk_buff *src_recvd_order_last;	/* Last skb send - for fast appending of new buffers */
	int32_t src_count;			/* Count of datagrams in list */
	int32_t src_bytes_total;		/* Total bytes in all received datagrams */

	struct sk_buff *dest_recvd_order;	/* sk buff list as sent by dest */
	struct sk_buff *dest_recvd_order_last;	/* Last skb send - for fast appending of new buffers */
	int32_t dest_count;			/* Count of datagrams in list */
	int32_t dest_bytes_total;		/* Total bytes in all received datagrams */

	int32_t data_limit;			/* Limit for tracked data */

	ecm_tracker_sender_state_t sender_state[ECM_TRACKER_SENDER_MAX];
						/* State of each sender */

	spinlock_t lock;			/* lock */

	int refs;				/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

int ecm_tracker_datagram_count = 0;		/* Counts the number of DATAGRAM data trackers right now */
spinlock_t ecm_tracker_datagram_lock;		/* Global lock for the tracker globals */

/*
 * ecm_trracker_datagram_connection_state_matrix[][]
 *	Matrix to convert from/to states to connection state
 */
static ecm_tracker_connection_state_t ecm_tracker_datagram_connection_state_matrix[ECM_TRACKER_SENDER_STATE_MAX][ECM_TRACKER_SENDER_STATE_MAX] =
{	/* 			Unknown						Establishing					Established					Closing					Closed					Fault */
	/* Unknown */		{ECM_TRACKER_CONNECTION_STATE_ESTABLISHING,	ECM_TRACKER_CONNECTION_STATE_ESTABLISHING,	ECM_TRACKER_CONNECTION_STATE_ESTABLISHED,	ECM_TRACKER_CONNECTION_STATE_FAULT,	ECM_TRACKER_CONNECTION_STATE_FAULT,	ECM_TRACKER_CONNECTION_STATE_FAULT},
	/* Establishing */	{ECM_TRACKER_CONNECTION_STATE_ESTABLISHING,	ECM_TRACKER_CONNECTION_STATE_ESTABLISHING,	ECM_TRACKER_CONNECTION_STATE_ESTABLISHED,	ECM_TRACKER_CONNECTION_STATE_FAULT,	ECM_TRACKER_CONNECTION_STATE_FAULT,	ECM_TRACKER_CONNECTION_STATE_FAULT},
	/* Established */	{ECM_TRACKER_CONNECTION_STATE_ESTABLISHED,	ECM_TRACKER_CONNECTION_STATE_ESTABLISHED,	ECM_TRACKER_CONNECTION_STATE_ESTABLISHED,	ECM_TRACKER_CONNECTION_STATE_CLOSING,	ECM_TRACKER_CONNECTION_STATE_CLOSING,	ECM_TRACKER_CONNECTION_STATE_FAULT},
	/* Closing */		{ECM_TRACKER_CONNECTION_STATE_FAULT,		ECM_TRACKER_CONNECTION_STATE_FAULT,		ECM_TRACKER_CONNECTION_STATE_CLOSING,		ECM_TRACKER_CONNECTION_STATE_CLOSING,	ECM_TRACKER_CONNECTION_STATE_CLOSING,	ECM_TRACKER_CONNECTION_STATE_FAULT},
	/* Closed */		{ECM_TRACKER_CONNECTION_STATE_FAULT,		ECM_TRACKER_CONNECTION_STATE_FAULT,		ECM_TRACKER_CONNECTION_STATE_CLOSING,		ECM_TRACKER_CONNECTION_STATE_CLOSING,	ECM_TRACKER_CONNECTION_STATE_CLOSED, 	ECM_TRACKER_CONNECTION_STATE_FAULT},
	/* Fault */		{ECM_TRACKER_CONNECTION_STATE_FAULT,		ECM_TRACKER_CONNECTION_STATE_FAULT,		ECM_TRACKER_CONNECTION_STATE_FAULT,		ECM_TRACKER_CONNECTION_STATE_FAULT,	ECM_TRACKER_CONNECTION_STATE_FAULT,	ECM_TRACKER_CONNECTION_STATE_FAULT},
};

/*
 * ecm_tracker_datagram_datagram_discard()
 *	Discard n number of datagrams at the head of the datagram list that were sent to the target
 */
static void ecm_tracker_datagram_datagram_discard(struct ecm_tracker_datagram_internal_instance *dtii, ecm_tracker_sender_type_t sender, int32_t n)
{
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	DEBUG_TRACE("%p: discard %u datagrams for %d\n", dtii, n, sender);

	/*
	 * Which list?
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		/*
		 * iterate n times and discard the buffers
		 */
		while (n) {
			struct sk_buff *skb;

			spin_lock_bh(&dtii->lock);

			skb = dtii->src_recvd_order;
			DEBUG_ASSERT(skb, "%p: bad list\n", dtii);

			dtii->src_recvd_order = skb->next;
			if (!dtii->src_recvd_order) {
				DEBUG_ASSERT(dtii->src_recvd_order_last == skb, "%p: bad list\n", dtii);
				dtii->src_recvd_order_last = NULL;
			} else {
				dtii->src_recvd_order->prev = NULL;
			}

			dtii->src_count--;
			DEBUG_ASSERT(dtii->src_count >= 0, "%p: bad total\n", dtii);
			dtii->src_bytes_total -= skb->truesize;
			ecm_tracker_data_total_decrease(skb->len, skb->truesize);
			DEBUG_ASSERT(dtii->src_bytes_total >= 0, "%p: bad bytes total\n", dtii);

			spin_unlock_bh(&dtii->lock);
			kfree_skb(skb);

			n--;
		}
		return;
	}

	/*
	 * iterate n times and discard the buffers
	 */
	while (n) {
		struct sk_buff *skb;

		spin_lock_bh(&dtii->lock);

		skb = dtii->dest_recvd_order;
		DEBUG_ASSERT(skb, "%p: bad list\n", dtii);

		dtii->dest_recvd_order = skb->next;
		if (!dtii->dest_recvd_order) {
			DEBUG_ASSERT(dtii->dest_recvd_order_last == skb, "%p: bad list\n", dtii);
			dtii->dest_recvd_order_last = NULL;
		} else {
			dtii->dest_recvd_order->prev = NULL;
		}

		dtii->dest_count--;
		DEBUG_ASSERT(dtii->dest_count >= 0, "%p: bad total\n", dtii);
		dtii->dest_bytes_total -= skb->truesize;
		ecm_tracker_data_total_decrease(skb->len, skb->truesize);
		DEBUG_ASSERT(dtii->dest_bytes_total >= 0, "%p: bad bytes total\n", dtii);

		spin_unlock_bh(&dtii->lock);
		kfree_skb(skb);

		n--;
	}
}

/*
 * ecm_tracker_datagram_discard_all()
 *	Discard all tracked data
 */
static void ecm_tracker_datagram_discard_all(struct ecm_tracker_datagram_internal_instance *dtii)
{
	int32_t src_count;
	int32_t dest_count;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	spin_lock_bh(&dtii->lock);
	src_count = dtii->src_count;
	dest_count = dtii->dest_count;
	spin_unlock_bh(&dtii->lock);

	/*
	 * Destroy all datagrams
	 */
	DEBUG_TRACE("%p: destroy all (src count: %d, dest_count: %d)\n", dtii, src_count, dest_count);
	ecm_tracker_datagram_datagram_discard(dtii, ECM_TRACKER_SENDER_TYPE_SRC, src_count);
	ecm_tracker_datagram_datagram_discard(dtii, ECM_TRACKER_SENDER_TYPE_DEST, dest_count);
}
EXPORT_SYMBOL(ecm_tracker_datagram_discard_all);

/*
 * ecm_tracker_datagram_discard_all_callback()
 *	Discard all tracked data
 */
static void ecm_tracker_datagram_discard_all_callback(struct ecm_tracker_instance *ti)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	ecm_tracker_datagram_discard_all(dtii);
}

/*
 * ecm_tracker_datagram_ref()
 */
static void ecm_tracker_datagram_ref(struct ecm_tracker_datagram_internal_instance *dtii)
{

	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	spin_lock_bh(&dtii->lock);

	dtii->refs++;
	DEBUG_ASSERT(dtii->refs > 0, "%p: ref wrap", dtii);
	DEBUG_TRACE("%p: ref %d\n", dtii, dtii->refs);

	spin_unlock_bh(&dtii->lock);
}

/*
 * ecm_tracker_datagram_ref_callback()
 */
static void ecm_tracker_datagram_ref_callback(struct ecm_tracker_instance *ti)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	ecm_tracker_datagram_ref(dtii);
}

/*
 * ecm_tracker_datagram_deref()
 */
static int ecm_tracker_datagram_deref(struct ecm_tracker_datagram_internal_instance *dtii)
{

	int refs;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	spin_lock_bh(&dtii->lock);
	dtii->refs--;
	refs = dtii->refs;
	DEBUG_ASSERT(dtii->refs >= 0, "%p: ref wrap", dtii);
	DEBUG_TRACE("%p: deref %d\n", dtii, dtii->refs);

	if (dtii->refs > 0) {
		spin_unlock_bh(&dtii->lock);
		return refs;
	}
	spin_unlock_bh(&dtii->lock);

	DEBUG_TRACE("%p: final\n", dtii);

	/*
	 * Destroy all datagrams
	 */
	ecm_tracker_datagram_datagram_discard(dtii, ECM_TRACKER_SENDER_TYPE_SRC, dtii->src_count);
	ecm_tracker_datagram_datagram_discard(dtii, ECM_TRACKER_SENDER_TYPE_DEST, dtii->dest_count);

	spin_lock_bh(&ecm_tracker_datagram_lock);
	ecm_tracker_datagram_count--;
	DEBUG_ASSERT(ecm_tracker_datagram_count >= 0, "%p: tracker count wrap", dtii);
	spin_unlock_bh(&ecm_tracker_datagram_lock);

	DEBUG_INFO("%p: Udp tracker final\n", dtii);
	DEBUG_CLEAR_MAGIC(dtii);
	kfree(dtii);

	return 0;
}

/*
 * _ecm_tracker_datagram_deref_callback()
 */
static int ecm_tracker_datagram_deref_callback(struct ecm_tracker_instance *ti)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	return ecm_tracker_datagram_deref(dtii);
}

/*
 * ecm_tracker_datagram_datagram_count_get()
 *	Return number of available datagrams sent to the specified target
 */
static int32_t ecm_tracker_datagram_datagram_count_get(struct ecm_tracker_datagram_internal_instance *dtii, ecm_tracker_sender_type_t sender)
{
	int32_t count;

	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	/*
	 * Which list?
	 */
	spin_lock_bh(&dtii->lock);
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		count = dtii->src_count;
	} else {
		count = dtii->dest_count;
	}
	spin_unlock_bh(&dtii->lock);

	DEBUG_TRACE("%p: datagram count get for %d is %d\n", dtii, sender, count);

	return count;
}

/*
 * ecm_tracker_datagram_datagram_count_get_callback()
 *	Return number of available datagrams sent to the specified target
 */
static int32_t ecm_tracker_datagram_datagram_count_get_callback(struct ecm_tracker_instance *ti, ecm_tracker_sender_type_t sender)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	return ecm_tracker_datagram_datagram_count_get(dtii, sender);
}

/*
 * ecm_tracker_datagram_datagram_discard_callback()
 *	Discard n number of datagrams at the head of the datagram list that were sent to the target
 */
static void ecm_tracker_datagram_datagram_discard_callback(struct ecm_tracker_instance *ti, ecm_tracker_sender_type_t sender, int32_t n)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;

	ecm_tracker_datagram_datagram_discard(dtii, sender, n);
}

/*
 * ecm_tracker_datagram_datagram_size_get()
 *	Return size in bytes of datagram at index i that was sent to the target
 */
static int32_t ecm_tracker_datagram_datagram_size_get(struct ecm_tracker_datagram_instance *uti, ecm_tracker_sender_type_t sender, int32_t i)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)uti;

	int32_t size;
	struct sk_buff *skb;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	/*
	 * Which list?
	 */
	spin_lock_bh(&dtii->lock);
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		skb = dtii->src_recvd_order;
	} else {
		skb = dtii->dest_recvd_order;
	}

	/*
	 * Iterate to the i'th datagram
	 */
	while (i) {
		DEBUG_ASSERT(skb, "%p: index bad\n", dtii);
		skb = skb->next;
		i--;
	}
	DEBUG_ASSERT(skb, "%p: index bad\n", dtii);
	size = skb->len;
	spin_unlock_bh(&dtii->lock);
	return size;
}
EXPORT_SYMBOL(ecm_tracker_datagram_datagram_size_get);

/*
 * ecm_tracker_datagram_datagram_size_get_callback()
 *	Return size in bytes of datagram at index i that was sent to the target
 */
static int32_t ecm_tracker_datagram_datagram_size_get_callback(struct ecm_tracker_instance *ti, ecm_tracker_sender_type_t sender, int32_t i)
{
	struct ecm_tracker_datagram_instance *uti = (struct ecm_tracker_datagram_instance *)ti;

	return ecm_tracker_datagram_datagram_size_get(uti, sender, i);
}

/*
 * ecm_tracker_datagram_datagram_read()
 *	Read size bytes from datagram at index i into the buffer
 */
static int ecm_tracker_datagram_datagram_read(struct ecm_tracker_datagram_instance *uti, ecm_tracker_sender_type_t sender, int32_t i, int32_t offset, int32_t size, void *buffer)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)uti;
	int res;
	struct sk_buff *skb;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);
	DEBUG_TRACE("%p: datagram %d read at offset %d for %d bytes for %d\n", dtii, i, offset, size, sender);

	/*
	 * Which list?
	 */
	spin_lock_bh(&dtii->lock);
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		skb = dtii->src_recvd_order;
	} else {
		skb = dtii->dest_recvd_order;
	}

	/*
	 * Iterate to the i'th datagram
	 */
	while (i) {
		DEBUG_ASSERT(skb, "%p: index bad\n", dtii);
		skb = skb->next;
		i--;
	}
	DEBUG_ASSERT(skb, "%p: index bad\n", dtii);

	/*
	 * Perform read
	 */
	res = skb_copy_bits(skb, offset, buffer, (unsigned int)size);

	spin_unlock_bh(&dtii->lock);

	return res;
}
EXPORT_SYMBOL(ecm_tracker_datagram_datagram_read);

/*
 * ecm_tracker_datagram_datagram_read_callback()
 *	Read size bytes from datagram at index i into the buffer
 */
static int ecm_tracker_datagram_datagram_read_callback(struct ecm_tracker_instance *ti, ecm_tracker_sender_type_t sender, int32_t i, int32_t offset, int32_t size, void *buffer)
{
	struct ecm_tracker_datagram_instance *uti = (struct ecm_tracker_datagram_instance *)ti;

	return ecm_tracker_datagram_datagram_read(uti, sender, i, offset, size, buffer);
}

/*
 * ecm_tracker_datagram_datagram_add()
 *	Append the datagram onto the tracker queue for the given target
 */
static bool ecm_tracker_datagram_datagram_add(struct ecm_tracker_datagram_instance *uti, ecm_tracker_sender_type_t sender, struct sk_buff *skb)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)uti;
	struct sk_buff *skbc;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);
	DEBUG_TRACE("%p: datagram %p add for %d\n", dtii, skb, sender);

	/*
	 * Clone the packet
	 */
	skbc = skb_clone(skb, GFP_ATOMIC | __GFP_NOWARN);
	if (!skbc) {
		DEBUG_WARN("%p: Failed to clone packet %p\n", dtii, skb);
		return false;
	}
	DEBUG_TRACE("%p: cloned %p to %p\n", dtii, skb, skbc);

	/*
	 * Are we within instance limit?
	 */
	spin_lock_bh(&dtii->lock);
	DEBUG_ASSERT((dtii->src_bytes_total + dtii->dest_bytes_total + skbc->truesize) > 0, "%p: bad total\n", dtii);
	if ((dtii->src_bytes_total + dtii->dest_bytes_total + skbc->truesize) > dtii->data_limit) {
		DEBUG_TRACE("%p: over limit\n", dtii);
		spin_unlock_bh(&dtii->lock);
		kfree_skb(skbc);
		return false;
	}

	/*
	 * Within global limit?
	 */
	if (!ecm_tracker_data_total_increase(skbc->len, skbc->truesize)) {
		DEBUG_TRACE("%p: over global limit\n", dtii);
		spin_unlock_bh(&dtii->lock);
		kfree_skb(skbc);
		return false;
	}

	/*
	 * Which list?
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		skbc->next = NULL;
		skbc->prev = dtii->src_recvd_order_last;
		dtii->src_recvd_order_last = skbc;
		if (skbc->prev) {
			skbc->prev->next = skbc;
		} else {
			DEBUG_ASSERT(dtii->src_recvd_order == NULL, "%p: bad list\n", dtii);
			dtii->src_recvd_order = skbc;
		}

		dtii->src_count++;
		DEBUG_ASSERT(dtii->src_count > 0, "%p: bad total\n", dtii);
		dtii->src_bytes_total += skbc->truesize;
		spin_unlock_bh(&dtii->lock);
		return true;
	}

	skbc->next = NULL;
	skbc->prev = dtii->dest_recvd_order_last;
	dtii->dest_recvd_order_last = skbc;
	if (skbc->prev) {
		skbc->prev->next = skbc;
	} else {
		DEBUG_ASSERT(dtii->dest_recvd_order == NULL, "%p: bad list\n", dtii);
		dtii->dest_recvd_order = skbc;
	}

	dtii->dest_count++;
	DEBUG_ASSERT(dtii->dest_count > 0, "%p: bad total\n", dtii);
	dtii->dest_bytes_total += skbc->truesize;
	spin_unlock_bh(&dtii->lock);
	return true;
}
EXPORT_SYMBOL(ecm_tracker_datagram_datagram_add);

/*
 * _ecm_tracker_datagram_datagram_add_callback()
 *	Append the datagram onto the tracker queue for the given target
 */
static bool ecm_tracker_datagram_datagram_add_callback(struct ecm_tracker_instance *ti, ecm_tracker_sender_type_t sender, struct sk_buff *skb)
{
	struct ecm_tracker_datagram_instance *uti = (struct ecm_tracker_datagram_instance *)ti;
	return ecm_tracker_datagram_datagram_add(uti, sender, skb);
}

/*
 * ecm_tracker_datagram_data_total_get_callback()
 *	Return total tracked data
 */
static int32_t ecm_tracker_datagram_data_total_get_callback(struct ecm_tracker_instance *ti)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	int32_t data_total;

	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	spin_lock_bh(&dtii->lock);
	data_total = dtii->src_bytes_total + dtii->dest_bytes_total;
	spin_unlock_bh(&dtii->lock);

	return data_total;
}

/*
 * ecm_tracker_datagram_data_limit_get_callback()
 *	Return tracked data limit
 */
static int32_t ecm_tracker_datagram_data_limit_get_callback(struct ecm_tracker_instance *ti)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	int32_t data_limit;

	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	spin_lock_bh(&dtii->lock);
	data_limit = dtii->data_limit;
	spin_unlock_bh(&dtii->lock);

	return data_limit;
}

/*
 * ecm_tracker_datagram_data_limit_set_callback()
 *	Set tracked data limit
 */
static void ecm_tracker_datagram_data_limit_set_callback(struct ecm_tracker_instance *ti, int32_t data_limit)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	spin_lock_bh(&dtii->lock);
	dtii->data_limit = data_limit;
	spin_unlock_bh(&dtii->lock);
}

/*
 * ecm_tracker_datagram_state_update_callback()
 * 	Update connection state based on the knowledge we have and the skb given
 */
static void ecm_tracker_datagram_state_update_callback(struct ecm_tracker_instance *ti, ecm_tracker_sender_type_t sender, struct ecm_tracker_ip_header *ip_hdr, struct sk_buff *skb)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	/*
	 * As long as a sender has seen data then we consider the sender established
	 */
	spin_lock_bh(&dtii->lock);
	dtii->sender_state[sender] = ECM_TRACKER_SENDER_STATE_ESTABLISHED;
	spin_unlock_bh(&dtii->lock);
}

/*
 * ecm_tracker_datagram_state_get_callback()
 * 	Get state
 */
static void ecm_tracker_datagram_state_get_callback(struct ecm_tracker_instance *ti, ecm_tracker_sender_state_t *src_state,
					ecm_tracker_sender_state_t *dest_state, ecm_tracker_connection_state_t *state, ecm_db_timer_group_t *tg)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);
	spin_lock_bh(&dtii->lock);
	*src_state = dtii->sender_state[ECM_TRACKER_SENDER_TYPE_SRC];
	*dest_state = dtii->sender_state[ECM_TRACKER_SENDER_TYPE_DEST];
	spin_unlock_bh(&dtii->lock);
	*state = ecm_tracker_datagram_connection_state_matrix[*src_state][*dest_state];
	*tg = ECM_DB_TIMER_GROUPS_CONNECTION_GENERIC_TIMEOUT;
}

/*
 * ecm_tracker_datagram_xml_state_get_callback()
 *	Return an XML state element
 */
static int ecm_tracker_datagram_xml_state_get_callback(struct ecm_tracker_instance *ti, char *buf, int buf_sz)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)ti;
	int32_t src_count;
	int32_t src_bytes_total;
	int32_t dest_count;
	int32_t dest_bytes_total;
	int32_t data_limit;
	ecm_tracker_sender_state_t sender_state[ECM_TRACKER_SENDER_MAX];
	ecm_tracker_connection_state_t connection_state;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);

	/*
	 * Capture state
	 */
	spin_lock_bh(&dtii->lock);
	src_count = dtii->src_count;
	src_bytes_total = dtii->src_bytes_total;
	dest_count = dtii->dest_count;
	dest_bytes_total = dtii->dest_bytes_total;
	data_limit = dtii->data_limit;
	sender_state[ECM_TRACKER_SENDER_TYPE_SRC] = dtii->sender_state[ECM_TRACKER_SENDER_TYPE_SRC];
	sender_state[ECM_TRACKER_SENDER_TYPE_DEST] = dtii->sender_state[ECM_TRACKER_SENDER_TYPE_DEST];
	spin_unlock_bh(&dtii->lock);
	connection_state = ecm_tracker_datagram_connection_state_matrix[sender_state[ECM_TRACKER_SENDER_TYPE_SRC]][sender_state[ECM_TRACKER_SENDER_TYPE_DEST]];

	return snprintf(buf, buf_sz, "<datagram_tracker src_count=\"%d\" src_bytes_total=\"%d\" "
			"dest_count=\"%d\" dest_bytes_total=\"%d\" data_limit=\"%d\" timer_group=\"%d\""
			" src_sender_state=\"%s\" dest_sender_state=\"%s\" connection_state=\"%s\"/>\n",
			src_count,
			src_bytes_total,
			dest_count,
			dest_bytes_total,
			data_limit,
			ECM_DB_TIMER_GROUPS_CONNECTION_GENERIC_TIMEOUT,
			ecm_tracker_sender_state_to_string(sender_state[ECM_TRACKER_SENDER_TYPE_SRC]),
			ecm_tracker_sender_state_to_string(sender_state[ECM_TRACKER_SENDER_TYPE_DEST]),
			ecm_tracker_connection_state_to_string(connection_state));
}

/*
 * ecm_tracker_datagram_init()
 *	Initialise the two host addresses that define the two directions we track data for
 */
void ecm_tracker_datagram_init(struct ecm_tracker_datagram_instance *uti, int32_t data_limit)
{
	struct ecm_tracker_datagram_internal_instance *dtii = (struct ecm_tracker_datagram_internal_instance *)uti;
	DEBUG_CHECK_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC, "%p: magic failed", dtii);
	DEBUG_TRACE("%p: init tracker\n", uti);

	spin_lock_bh(&dtii->lock);
	dtii->data_limit = data_limit;
	spin_unlock_bh(&dtii->lock);
}
EXPORT_SYMBOL(ecm_tracker_datagram_init);

/*
 * ecm_tracker_datagram_alloc()
 */
struct ecm_tracker_datagram_instance *ecm_tracker_datagram_alloc(void)
{
	struct ecm_tracker_datagram_internal_instance *dtii;

	dtii = (struct ecm_tracker_datagram_internal_instance *)kzalloc(sizeof(struct ecm_tracker_datagram_internal_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!dtii) {
		DEBUG_WARN("Failed to allocate datagram tracker instance\n");
		return NULL;
	}

	dtii->datagram_base.base.ref = ecm_tracker_datagram_ref_callback;
	dtii->datagram_base.base.deref = ecm_tracker_datagram_deref_callback;
	dtii->datagram_base.base.datagram_count_get = ecm_tracker_datagram_datagram_count_get_callback;
	dtii->datagram_base.base.datagram_discard = ecm_tracker_datagram_datagram_discard_callback;
	dtii->datagram_base.base.datagram_read = ecm_tracker_datagram_datagram_read_callback;
	dtii->datagram_base.base.datagram_size_get = ecm_tracker_datagram_datagram_size_get_callback;
	dtii->datagram_base.base.datagram_add = ecm_tracker_datagram_datagram_add_callback;
	dtii->datagram_base.base.discard_all = ecm_tracker_datagram_discard_all_callback;
	dtii->datagram_base.base.data_total_get = ecm_tracker_datagram_data_total_get_callback;
	dtii->datagram_base.base.data_limit_get = ecm_tracker_datagram_data_limit_get_callback;
	dtii->datagram_base.base.data_limit_set = ecm_tracker_datagram_data_limit_set_callback;
	dtii->datagram_base.base.state_update = ecm_tracker_datagram_state_update_callback;
	dtii->datagram_base.base.state_get = ecm_tracker_datagram_state_get_callback;
	dtii->datagram_base.base.xml_state_get = ecm_tracker_datagram_xml_state_get_callback;

	// GGG TODO IMPLEMENT METHODS SPECIFIC TO WORKING WITH datagram e.g. reading without worrying about the datagram header content

	spin_lock_init(&dtii->lock);

	dtii->refs = 1;
	DEBUG_SET_MAGIC(dtii, ECM_TRACKER_DATAGRAM_INSTANCE_MAGIC);

	spin_lock_bh(&ecm_tracker_datagram_lock);
	ecm_tracker_datagram_count++;
	DEBUG_ASSERT(ecm_tracker_datagram_count > 0, "%p: datagram tracker count wrap\n", dtii);
	spin_unlock_bh(&ecm_tracker_datagram_lock);

	DEBUG_TRACE("DATAGRAM tracker created %p\n", dtii);
	return (struct ecm_tracker_datagram_instance *)dtii;
}
EXPORT_SYMBOL(ecm_tracker_datagram_alloc);

/*
 * ecm_tracker_datagram_module_init()
 */
int ecm_tracker_datagram_module_init(void)
{
	DEBUG_INFO("Datagram Tracker Module init\n");
	spin_lock_init(&ecm_tracker_datagram_lock);
	return 0;
}
EXPORT_SYMBOL(ecm_tracker_datagram_module_init);

/*
 * ecm_tracker_datagram_module_exit()
 */
void ecm_tracker_datagram_module_exit(void)
{
	DEBUG_INFO("Datagram Tracker Module exit\n");
}
EXPORT_SYMBOL(ecm_tracker_datagram_module_exit);
