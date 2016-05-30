/*
 **************************************************************************
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
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

/*
 * ecm_bond_notifier.c
 * 	Bonding notifier functionality.
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

#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <linux/if_bonding.h>
#include <net/arp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
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
#define DEBUG_LEVEL ECM_BOND_NOTIFIER_DEBUG_LEVEL

#include <nss_api_if.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_tracker_datagram.h"
#include "ecm_db.h"
#include "ecm_classifier_default.h"
#include "ecm_front_end_ipv4.h"
// GGG #include "ecm_front_end_ipv6.h"

/*
 * Locking of the classifier - concurrency control
 */
static spinlock_t ecm_bond_notifier_lock;			/* Protect against SMP access between netfilter, events and private threaded function. */

/*
 * SysFS linkage
 */
static struct sys_device ecm_bond_notifier_sys_dev;		/* SysFS linkage */

/*
 * General operational control
 */
static int ecm_bond_notifier_stopped = 0;			/* When non-zero further traffic will not be processed */

/*
 * ecm_bond_notifier_bond_cb
 *	Bond driver notifier
 */
static struct bond_cb ecm_bond_notifier_bond_cb;

/*
 * NSS Context for LAG function
 */
static void *ecm_bond_notifier_nss_context = NULL;		/* Registration for LAG */

/*
 * ecm_bond_notifier_send_lag_state()
 *	Send the currnet LAG state of a physical interface that has changed state in the bonding driver.
 */
static nss_tx_status_t ecm_bond_notifier_send_lag_state(struct nss_ctx_instance *nss_ctx, struct net_device *slave)
{
	int32_t lagid = 0;
	int32_t slave_ifnum;
	nss_tx_status_t nss_tx_status;
	struct nss_lag_msg nm;
	struct nss_lag_state_change *nlsc = NULL;

	DEBUG_INFO("Send LAG update for: %p (%s)\n", slave, slave->name);

	/*
	 * Can only handle interfaces known to the nss
	 */
	slave_ifnum = nss_cmn_get_interface_number(nss_ctx, slave);
	if (slave_ifnum < 0) {
		DEBUG_WARN("Not an NSS interface: %p\n", slave);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	/*
	 * Figure out the aggregation id of this slave
	 */
	memset(&nm, 0, sizeof(nm));
	if (netif_is_bond_slave(slave)) {
		lagid = bond_get_id(slave->master) + NSS_LAG0_INTERFACE_NUM;
	} else {
		lagid = NSS_LAG0_INTERFACE_NUM;
	}

	/*
	 * Construct a message to the NSS to update it
	 */
	nss_cmn_msg_init(&nm.cm, lagid,
			 NSS_TX_METADATA_LAG_STATE_CHANGE,
			 sizeof(struct nss_lag_state_change),
			 NULL, NULL);

	nlsc = &nm.msg.state;

	/*
	 * If the slave device IS a slave then this is an enslave, else it has been released
	 */
	if (netif_is_bond_slave(slave)) {
		nlsc->event = NSS_LAG_ENSLAVE;
		DEBUG_INFO("Enslave: %p (%s)\n", slave, slave->name);
	} else {
		nlsc->event = NSS_LAG_RELEASE;
		DEBUG_INFO("Release: %p (%s)\n", slave, slave->name);
	}

	nlsc->interface = slave_ifnum;

	nss_tx_status = nss_lag_tx(nss_ctx, &nm);
	if (nss_tx_status != NSS_TX_SUCCESS) {
		DEBUG_WARN("%p: Send LAG update failed, status: %d\n", slave, nss_tx_status);
		return NSS_TX_FAILURE;
	}
	DEBUG_TRACE("%p: Send LAG update sent\n", slave);
	return NSS_TX_SUCCESS;
}

/*
 * ecm_bond_notifier_bond_release()
 *	Callback when a slave device is released from slavedom and no longer a part of a bonded interface.
 */
static void ecm_bond_notifier_bond_release(struct net_device *slave_dev)
{
	/*
	 * If operations have stopped then do not process event
	 */
	DEBUG_INFO("Bond slave release: %p (%s)\n", slave_dev, slave_dev->name);
	spin_lock_bh(&ecm_bond_notifier_lock);
	if (unlikely(ecm_bond_notifier_stopped)) {
		DEBUG_WARN("Ignoring bond release event - stopped\n");
		spin_unlock_bh(&ecm_bond_notifier_lock);
		return;
	}
	spin_unlock_bh(&ecm_bond_notifier_lock);
	ecm_bond_notifier_send_lag_state(ecm_bond_notifier_nss_context, slave_dev);
}

/*
 * ecm_bond_notifier_bond_enslave()
 *	Callback when a device is enslaved by a LAG master device
 */
static void ecm_bond_notifier_bond_enslave(struct net_device *slave_dev)
{
	/*
	 * If operations have stopped then do not process event
	 */
	DEBUG_INFO("Bond slave enslave: %p (%s)\n", slave_dev, slave_dev->name);
	spin_lock_bh(&ecm_bond_notifier_lock);
	if (unlikely(ecm_bond_notifier_stopped)) {
		DEBUG_WARN("Ignoring bond enslave event - stopped\n");
		spin_unlock_bh(&ecm_bond_notifier_lock);
		return;
	}
	spin_unlock_bh(&ecm_bond_notifier_lock);
	ecm_bond_notifier_send_lag_state(ecm_bond_notifier_nss_context, slave_dev);
}

/*
 * ecm_bond_notifier_bond_link_up()
 *	Callback when a device is enslaved by a LAG master device
 */
static void ecm_bond_notifier_bond_link_up(struct net_device *slave_dev)
{
	/*
	 * If operations have stopped then do not process event
	 */
	spin_lock_bh(&ecm_bond_notifier_lock);
	if (unlikely(ecm_bond_notifier_stopped)) {
		DEBUG_WARN("Ignoring bond enslave event - stopped\n");
		spin_unlock_bh(&ecm_bond_notifier_lock);
		return;
	}
	spin_unlock_bh(&ecm_bond_notifier_lock);

	/*
	 * Tricky to handle, this one.
	 * A net device that is a LAG slave has become active.
	 * Due to the heiarchical nature of network topologies, this can change the packet transmit path
	 * for any connection that is using a device that it sitting "higher" in the heirarchy.
	 * Now, we could get the lag master, iterate all of the connections looking for this master in the connection heirarchy lists of those connections.
	 * This would be INCREDIBLY SLOW.
	 * GGG TODO Interface heirarchy construct is in its infancy right now, eventually you will be able to say
	 * "given this LAG master I want to iterate all depending connections irrespective of where in the heirarchy the master is or any heiarchical relationship there is"
 	 * Anyway, for simplicity and speed right now, just cause a system wide regeneration!
	 */
	ecm_db_classifier_generation_change();
}

/*
 * ecm_bond_notifier_lag_event_cb()
 *	Handle LAG event from the NSS driver
 */
static void ecm_bond_notifier_lag_event_cb(void *if_ctx, struct nss_lag_msg *msg)
{
	/*
	 * If operations have stopped then do not process event
	 */
	spin_lock_bh(&ecm_bond_notifier_lock);
	if (unlikely(ecm_bond_notifier_stopped)) {
		DEBUG_WARN("Ignoring LAG event event - stopped\n");
		spin_unlock_bh(&ecm_bond_notifier_lock);
		return;
	}
	spin_unlock_bh(&ecm_bond_notifier_lock);

	/*
	 * GGG TODO Figure out if there is anything we need to do here, the old CM did nothing..
	 */
	switch (msg->cm.type)
	{
		default:
			DEBUG_INFO("Unknown LAG event from NSS: %d", msg->cm.type);
			break;
	}
}

/*
 * ecm_bond_notifier_get_stop()
 */
static ssize_t ecm_bond_notifier_get_stop(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_bond_notifier_lock);
	num = ecm_bond_notifier_stopped;
	spin_unlock_bh(&ecm_bond_notifier_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

void ecm_bond_notifier_stop(int num)
{
	/*
	 * Operate under our locks and stop further processing of packets
	 */
	spin_lock_bh(&ecm_bond_notifier_lock);
	ecm_bond_notifier_stopped = num;
	spin_unlock_bh(&ecm_bond_notifier_lock);
}
EXPORT_SYMBOL(ecm_bond_notifier_stop);

/*
 * ecm_bond_notifier_set_stop()
 */
static ssize_t ecm_bond_notifier_set_stop(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	char num_buf[12];
	int num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count > 11) {
		return 0;
	}
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%d", &num);
	DEBUG_TRACE("ecm_bond_notifier_stop = %d\n", num);

	ecm_bond_notifier_stop(num);

	return count;
}

/*
 * SysFS attributes for the default classifier itself.
 */
static SYSDEV_ATTR(stop, 0644, ecm_bond_notifier_get_stop, ecm_bond_notifier_set_stop);

/*
 * SysFS class
 * SysFS control points can be found at /sys/devices/system/ecm_bond_notifier/ecm_bond_notifierX/
 */
static struct sysdev_class ecm_bond_notifier_sysclass = {
	.name = "ecm_bond_notifier",
};

/*
 * ecm_bond_notifier_init()
 */
int ecm_bond_notifier_init(void)
{
	int result;
	DEBUG_INFO("ECM Bonding Notifier init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_bond_notifier_lock);

	/*
	 * Register the sysfs class
	 */
	result = sysdev_class_register(&ecm_bond_notifier_sysclass);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS class %d\n", result);
		return result;
	}

	/*
	 * Register SYSFS device control
	 */
	memset(&ecm_bond_notifier_sys_dev, 0, sizeof(ecm_bond_notifier_sys_dev));
	ecm_bond_notifier_sys_dev.id = 0;
	ecm_bond_notifier_sys_dev.cls = &ecm_bond_notifier_sysclass;
	result = sysdev_register(&ecm_bond_notifier_sys_dev);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS device %d\n", result);
		goto task_cleanup_1;
	}

	result = sysdev_create_file(&ecm_bond_notifier_sys_dev, &attr_stop);
	if (result) {
		DEBUG_ERROR("Failed to register stop file %d\n", result);
		goto task_cleanup_2;
	}

	/*
	 * Register Link Aggregation interfaces with NSS driver
	 */
	ecm_bond_notifier_nss_context = nss_register_lag_if(NSS_LAG0_INTERFACE_NUM, NULL, ecm_bond_notifier_lag_event_cb, NULL);
	ecm_bond_notifier_nss_context = nss_register_lag_if(NSS_LAG1_INTERFACE_NUM, NULL, ecm_bond_notifier_lag_event_cb, NULL);

	/*
	 * Register Link Aggregation callbacks with the bonding driver
	 */
	ecm_bond_notifier_bond_cb.bond_cb_link_up = ecm_bond_notifier_bond_link_up;
	ecm_bond_notifier_bond_cb.bond_cb_release = ecm_bond_notifier_bond_release;
	ecm_bond_notifier_bond_cb.bond_cb_enslave = ecm_bond_notifier_bond_enslave;
	bond_register_cb(&ecm_bond_notifier_bond_cb);

	return 0;

task_cleanup_2:
	sysdev_unregister(&ecm_bond_notifier_sys_dev);
task_cleanup_1:
	sysdev_class_unregister(&ecm_bond_notifier_sysclass);

	return result;
}
EXPORT_SYMBOL(ecm_bond_notifier_init);

/*
 * ecm_bond_notifier_exit()
 */
void ecm_bond_notifier_exit(void)
{
	DEBUG_INFO("ECM Bonding Notifier exit\n");

	/*
	 * Unregister from the bond driver
	 */
	bond_unregister_cb();

	/*
	 * Unregister Link Aggregation interfaces with NSS driver
	 */
	nss_unregister_lag_if(NSS_LAG0_INTERFACE_NUM);
	nss_unregister_lag_if(NSS_LAG1_INTERFACE_NUM);

	sysdev_unregister(&ecm_bond_notifier_sys_dev);
	sysdev_class_unregister(&ecm_bond_notifier_sysclass);

}
EXPORT_SYMBOL(ecm_bond_notifier_exit);
