#include <linux/jhash.h>
#include "auth_comm.h"
#include "auth_core.h"
#include "auth_user.h"

#define AUTH_USER_HASH_SIZE       (1 << 15)
#define AUTH_USER_HASH_MASK       (AUTH_USER_HASH_SIZE - 1)
#define WATCHDOG_EXPIRED_INTVAL		(300 * 1000) /*millisecond*/

struct auth_user_hash {
	struct hlist_head slots[AUTH_USER_HASH_SIZE];
	uint32_t n_slot_user[AUTH_USER_HASH_SIZE];
	spinlock_t lock;
};

struct auth_user_set {
	struct user_info *infos;
	uint32_t nc_user;
	uint64_t tm_stamp;	/*used as request identifier*/
	uint32_t nc_used_user;
	uint32_t valid;
};

static struct timer_list s_watchdog_tm;	/*tm for forcing free timeout user*/
static uint32_t s_watchdog_intval_jf = 0;	/*unit is millisecond*/
static uint32_t s_user_off_intval_jf = 0;
static uint32_t s_user_timeout_intval_jf = 0;
static struct auth_user_hash s_user_hash;
static struct auth_user_set s_user_set;

#define OS_INIT_TIMER(_timer, _fn, _arg)	\
do {							\
	init_timer(_timer);				\
	(_timer)->function = (_fn);			\
	(_timer)->data = (unsigned long)(_arg);		\
} while (0)

#define OS_SET_TIMER(_timer, _ms)	\
	mod_timer(_timer, jiffies + ((_ms)*HZ)/1000)

#define OS_CANCEL_TIMER(_timer)		del_timer_sync(_timer)


static uint32_t auth_user_mac_hash(const unsigned char *mac)
{
	uint32_t n = 0, h = 0;
	unsigned char hash_data[ETH_ALEN + 2] = {0};

	n = ETH_ALEN + 2;
	memcpy(hash_data, mac, ETH_ALEN);
	h = jhash2((const u32 *)hash_data, n / sizeof(u32), *(uint32_t *)(mac + 2));
	return  ((u64)h * n) >> 32;
}


static struct user_node *user_create(const struct user_info *user_info)
{
	struct user_node *user = NULL;
	user = AUTH_NEW(struct user_node);
	if (user == NULL) {
		AUTH_ERROR("create user failed for no memory.\n");
		return user;
	}
	memset(user, 0, sizeof(struct user_node));
	INIT_HLIST_NODE(&user->user_node);
	user->info.ipv4 = user_info->ipv4;
	user->info.jf = jiffies;
	user->info.status = USER_OFFLINE;
	user->info.auth_type = UNKNOW_AUTH;
	memcpy(user->info.mac, user_info->mac, ETH_ALEN);
	AUTH_DEBUG("create a new user node.");
	return user;
}


void display_user(struct user_node *user)
{
	AUTH_DEBUG("***************DISPLAY USER START****************\n");
	AUTH_DEBUG("MAC:%02X:%02X:%02X:%02X:%02X:%02X.\n", 
				user->info.mac[0],  user->info.mac[1],  user->info.mac[2],
				user->info.mac[3],  user->info.mac[4],  user->info.mac[5]);
	AUTH_DEBUG("IPV4:%pI4 .\n", &user->info.ipv4);
	AUTH_DEBUG("Status:%u.\n", user->info.status);
	AUTH_DEBUG("Jiffes:%llu.\n", user->info.jf);
	AUTH_DEBUG("***************DISPLAY USER END****************\n");
}


void display_all_user(void)
{
	uint16_t slot_idx = 0;
	struct user_node *user = NULL;
	struct hlist_head *hslot = NULL;
	struct hlist_node *node = NULL;
	AUTH_DEBUG("***************DISPLAY ALL USER START****************\n");
	for (slot_idx = 0; slot_idx < AUTH_USER_HASH_SIZE; slot_idx++) {
		hslot = &s_user_hash.slots[slot_idx];
		hlist_for_each_entry(user, node, hslot, user_node) {
			display_user(user);
		}
	}
	AUTH_DEBUG("***************DISPLAY ALL USER END****************\n");
}


static void user_info_collet(uint64_t tm_stamp)
{
	#define MSECS_TO_SEC 1000	/*millisecond to second*/
	uint32_t total_user = 0;
	uint16_t slot_idx = 0, i = 0;
	struct user_info *info = NULL;
	struct user_node *user = NULL;
	struct hlist_head *hslot = NULL;
	struct hlist_node *node = NULL;

	if (s_user_set.valid) {
		kfree(s_user_set.infos);
		memset(&s_user_set, 0, sizeof(struct auth_user_set));
		s_user_set.infos = NULL;
	}

	for (slot_idx = 0; slot_idx < AUTH_USER_HASH_SIZE; slot_idx++) {
		total_user += s_user_hash.n_slot_user[slot_idx];
	}
	if (total_user == 0) {
		s_user_set.valid = 1;
		return;
	}
	s_user_set.infos = AUTH_NEW_N(struct user_info, total_user);
	if (s_user_set.infos == NULL) {
		AUTH_WARN("no mem.\n");
		s_user_set.valid = 0;
		return;
	}
	spin_lock_bh(&s_user_hash.lock);
	for (i = 0, slot_idx = 0; slot_idx < AUTH_USER_HASH_SIZE; slot_idx++) {
		hslot = &s_user_hash.slots[slot_idx];
		hlist_for_each_entry(user, node, hslot, user_node) {
			info  = &s_user_set.infos[i];
			info->ipv4 = user->info.ipv4;
			info->jf = jiffies_to_msecs(user->info.jf) / MSECS_TO_SEC;
			info->status = user->info.status;
			info->auth_type = user->info.auth_type;
			memcpy(info->mac, user->info.mac, ETH_ALEN);
			i++;
		}
	}
	spin_unlock_bh(&s_user_hash.lock);
	s_user_set.nc_user = total_user;
	s_user_set.tm_stamp = tm_stamp;
	s_user_set.nc_used_user = 0;
	s_user_set.valid = 1;
}


int auth_users_get(struct user_stat_assist *assist)
{
	uint16_t useable_cnt = 0, copy_cnt = 0;
	struct user_info *infos = NULL;
	unsigned long user_addr = 0;
	/*first or new request*/
	if (s_user_set.valid == 0 || assist->tm_stamp != s_user_set.tm_stamp) {
		user_info_collet(assist->tm_stamp);
	}
	if (s_user_set.valid == 0) {
		AUTH_WARN("collect user info failed.\n");
		return -1;
	}
	user_addr = assist->addr;
	useable_cnt = s_user_set.nc_user - s_user_set.nc_used_user;

	if (s_user_set.nc_user == 0) {
		assist->more = 0;
		assist->nc_user = 0;
		if (copy_to_user((void*)user_addr, (void*)assist, sizeof(struct user_stat_assist))) {
			AUTH_WARN("copy assist to user failed.\n");
			goto FAILED;
		}
		AUTH_DEBUG("No users.\n");
		return 0;
	}

	infos = &s_user_set.infos[s_user_set.nc_used_user];
	copy_cnt = min(assist->nc_element, useable_cnt);

	s_user_set.nc_used_user += copy_cnt;
	assist->more = (s_user_set.nc_user > s_user_set.nc_used_user ? 1 : 0);
	assist->nc_unused = s_user_set.nc_user - s_user_set.nc_used_user;
	assist->nc_user = copy_cnt;

	if (copy_to_user((void*)user_addr, (void*)assist, sizeof(struct user_stat_assist))) {
		AUTH_WARN("copy assist to user failed.\n");
		goto FAILED;
	}
	user_addr = (unsigned long)((void*)user_addr + sizeof(struct user_stat_assist));
	if (copy_to_user((void*)user_addr, (void*)infos, copy_cnt * sizeof(struct user_info))) {
		AUTH_WARN("copy user_info to user failed.\n");
		goto FAILED;
	}

	if (s_user_set.nc_used_user == s_user_set.nc_user) {
		kfree(s_user_set.infos);
		memset(&s_user_set, 0, sizeof(struct auth_user_set));
		s_user_set.infos = NULL;
	}
	AUTH_INFO("copy %u user.\n", copy_cnt);
	return 0;
FAILED:
	if (s_user_set.nc_user && (s_user_set.nc_used_user == s_user_set.nc_user)) {
		kfree(s_user_set.infos);
		memset(&s_user_set, 0, sizeof(struct auth_user_set));
		s_user_set.infos = NULL;
	}
	return -EFAULT;
}


int auth_user_status(struct user_node *user)
{
	return user->info.status;
}


/*no lock*/
struct  user_node *auth_user_get(const unsigned char *mac)
{
	uint32_t hkey = 0, existence = 0;
	struct hlist_head *hslot = NULL;
	struct hlist_node *node = NULL;
	struct user_node *user = NULL;

	hkey = auth_user_mac_hash(mac);
	hslot = &s_user_hash.slots[hkey & AUTH_USER_HASH_MASK];
	spin_lock_bh(&s_user_hash.lock);
	hlist_for_each_entry(user, node, hslot, user_node) {
		if (memcmp(user->info.mac, mac, ETH_ALEN) == 0) {
			existence = 1;
			break;
		}
	}
	spin_unlock_bh(&s_user_hash.lock);
	if (existence) {
		return user;
	}
	return NULL;
}


struct user_node *auth_user_add(struct user_info *user_info)
{
	uint32_t hkey = 0;
	struct user_node *user = NULL;
	struct hlist_head *hslot = NULL;

	user = auth_user_get(user_info->mac);
	if (user) {
		AUTH_DEBUG("user[%02x:%02x:%02x:%02x:%02x:%02x] already existence.\n", 
					user_info->mac[0], user_info->mac[1], user_info->mac[2],
					user_info->mac[3], user_info->mac[4], user_info->mac[5]);
		return user;
	}
	user = user_create(user_info);
	if (user == NULL) {
		return user;
	}
	hkey = auth_user_mac_hash(user->info.mac);
	#if DEBUG_ENABLE
	AUTH_DEBUG("[HKEY:%u;SLOT:%u;MAC:%02x:%02x:%02x:%02x:%02x:%02x].\n", 
				hkey, (hkey & AUTH_USER_HASH_MASK),
				user->info.mac[0],  user->info.mac[1],  user->info.mac[2],
				user->info.mac[3],  user->info.mac[4],  user->info.mac[5]);
	#endif
	spin_lock_bh(&s_user_hash.lock);
	hslot = &s_user_hash.slots[hkey & AUTH_USER_HASH_MASK];
	hlist_add_head(&user->user_node, hslot);
	s_user_hash.n_slot_user[hkey & AUTH_USER_HASH_MASK] ++;
	spin_unlock_bh(&s_user_hash.lock);
	return user;
}


int update_auth_user_auth_type(struct user_node *user, int type)
{
	if (user) {
		user->info.auth_type = type;
	}
	return 0;
}


int get_auth_user_auth_type(struct user_node *user)
{
	return user?user->info.auth_type:UNKNOW_AUTH;
}


int update_auth_user_status(struct user_node *user, int status)
{
	if (user && user->info.status != status) {
		user->info.status = status;
	}
	return 0;
}

int update_auth_user_ipv4(struct user_node *user, uint32_t ipv4)
{
	if (user && user->info.ipv4 != ipv4) {
		user->info.ipv4 = ipv4;
	}
	return 0;
}

uint32_t get_auth_user_ipv4(struct user_node *user)
{
	return user?user->info.ipv4 : 0;
}

int kick_off_all_auth_auto_users(void)
{
	int i = 0, slot_idx = 0;
	//struct user_info *info = NULL;
	struct user_node *user = NULL;
	struct hlist_head *hslot = NULL;
	struct hlist_node *node = NULL;
	spin_lock_bh(&s_user_hash.lock);
	for (i = 0, slot_idx = 0; slot_idx < AUTH_USER_HASH_SIZE; slot_idx++) {
		hslot = &s_user_hash.slots[slot_idx];
		hlist_for_each_entry(user, node, hslot, user_node) {
			if (user->info.auth_type == AUTO_AUTH) {
				user->info.status = USER_OFFLINE;
				i++;
			}
		}
	}
	spin_unlock_bh(&s_user_hash.lock);
	#if DEBUG_ENABLE
		AUTH_DEBUG("Kick off %u auto users totally.\n", i);
	#endif
	return 0;
}


int update_auth_users_stat(struct user_info *infos, uint16_t nc_user)
{
	uint16_t i = 0;
	struct user_node *user = NULL;
#if DEBUG_ENABLE
	char user_status[USER_STATUS_NUM][USER_STATUS_STR_LEN] = { {"OFFLINE"}, {"ONLINE"},};
#endif
	if (infos == NULL || nc_user == 0) {
		return 0;
	}
	for (i = 0; i < nc_user; i++) {
		user = auth_user_get(infos[i].mac);
		/*maybe a nonexistence user*/
		if (user == NULL) {
			continue;
		}
	#if DEBUG_ENABLE
		AUTH_DEBUG("Update user status from %s to %s success [MAC:%02X:%02X:%02X:%02X:%02X:%02X].\n", 
					user_status[user->info.status], user_status[infos[i].status],
					infos[i].mac[0], infos[i].mac[1], infos[i].mac[2],
					infos[i].mac[3], infos[i].mac[4], infos[i].mac[5]);
	#endif
		user->info.status = infos[i].status;
	}
	return 0;
}


int update_auth_user_active_tm(struct user_node *user)
{
	if (user) {
		user->info.jf = jiffies; 
	}
	return 0;
}


static int auth_user_del(uint16_t slot_idx, struct user_node *user)
{
	hlist_del(&user->user_node);
	kfree(user);
	s_user_hash.n_slot_user[slot_idx & AUTH_USER_HASH_MASK] --;
	return 0;
}


static void auth_user_clear(void)
{
	uint32_t  user_total = 0, slot_idx = 0, free_total = 0;
	struct hlist_head *hslot = NULL;
	struct user_node *user = NULL;
	struct hlist_node *node = NULL, *node_tmp = NULL;
	for (slot_idx = 0; slot_idx < AUTH_USER_HASH_SIZE; slot_idx++) {
		hslot = &s_user_hash.slots[slot_idx];
		user_total += s_user_hash.n_slot_user[slot_idx];
		hlist_for_each_entry_safe(user, node, node_tmp, hslot, user_node) {
				auth_user_del(slot_idx, user);
				user = NULL;
				free_total++;
		}
	}
	AUTH_DEBUG("Clear all user:[total=%u, free=%u].\n", user_total, free_total);
}


static void auth_user_watchdog_fn(unsigned long arg)
{
#if DEBUG_ENABLE
	uint32_t free_total = 0;
#endif
	uint32_t now_jf = jiffies;
	uint16_t slot_idx = 0;
	struct hlist_head *hslot = NULL;
	struct user_node *user = NULL;
	struct hlist_node *node = NULL, *node_tmp = NULL;

	spin_lock_bh(&s_user_hash.lock);
	for (slot_idx = 0; slot_idx < AUTH_USER_HASH_SIZE; slot_idx++) {
		hslot = &s_user_hash.slots[slot_idx];
		hlist_for_each_entry_safe(user, node, node_tmp, hslot, user_node) {
			if ((now_jf - user->info.jf) >= s_user_timeout_intval_jf) {
				#if DEBUG_ENABLE
					free_total++;
					AUTH_DEBUG("user del:%pI4h for timeout[last_jf:%lluu, timeout_jf:%u, now_jf:%u].\n", 
								&user->info.ipv4, user->info.jf, s_user_timeout_intval_jf, now_jf);
				#endif
				auth_user_del(slot_idx, user);
				user = NULL;
			}
			else if ((now_jf - user->info.jf) >= s_user_off_intval_jf) {
				#if DEBUG_ENABLE
				if (user->info.status == USER_ONLINE)
				{
					AUTH_DEBUG("user offline:%pI4h for timeout[last_jf:%llu, off_jf:%u, now_jf:%u].\n", 
								&user->info.ipv4, user->info.jf, s_user_off_intval_jf, now_jf);
				}
				#endif
				user->info.status = USER_OFFLINE;
			}
		}
	}
	OS_SET_TIMER(&s_watchdog_tm, s_watchdog_intval_jf);
	spin_unlock_bh(&s_user_hash.lock);
#if DEBUG_ENABLE
	if (free_total) {
		AUTH_DEBUG("Totally, free %u users for timeout.\n", free_total);
	}
#endif
}


static int watchdog_intval_valid_check(uint32_t mesc_intval)
{
	/*todo:sensitivity of checking user on/off */
	uint32_t jf = msecs_to_jiffies(mesc_intval);
	if (jf >= MAX_JIFFY_OFFSET) {
		return 0;
	}
	return 1;
}


/*update the timeout of watchdog timer*/
int watchdog_tm_update(uint32_t msecs_intval)
{
	if (watchdog_intval_valid_check(msecs_intval) == 0) {
		AUTH_WARN("WATCHDOG_EXPIRED_INTVAL[%u] invalid.\n", msecs_intval);
		return -1;
	}
	s_watchdog_intval_jf = msecs_to_jiffies(msecs_intval / 2);
	s_user_off_intval_jf = (s_watchdog_intval_jf << 1);
	s_user_timeout_intval_jf = (s_watchdog_intval_jf << 2);

	AUTH_DEBUG("WATCHDOG_INTVAL_JF:%u, USER_OFFLINE_JF:%u, USER_TIMEOUT_JF:%u\n",
				s_watchdog_intval_jf, s_user_off_intval_jf, s_user_timeout_intval_jf);
	OS_CANCEL_TIMER(&s_watchdog_tm);
	OS_SET_TIMER(&s_watchdog_tm, s_watchdog_intval_jf);
	return 0;
}


int auth_user_init(void)
{
	uint32_t idx = 0;
	OS_INIT_TIMER(&s_watchdog_tm, auth_user_watchdog_fn, NULL);

	memset(&s_user_set, 0, sizeof(struct auth_user_set));
	memset(&s_user_hash, 0, sizeof(struct auth_user_hash));
	for (idx = 0; idx < AUTH_USER_HASH_SIZE; idx++) {
		INIT_HLIST_HEAD(&s_user_hash.slots[idx]);
	}
	spin_lock_init(&s_user_hash.lock);

	s_watchdog_intval_jf = msecs_to_jiffies(WATCHDOG_EXPIRED_INTVAL);	/*unit is millsecods*/
	s_user_off_intval_jf = (s_watchdog_intval_jf << 1);
	s_user_timeout_intval_jf = (s_watchdog_intval_jf << 2);
	OS_SET_TIMER(&s_watchdog_tm, s_watchdog_intval_jf);
	AUTH_DEBUG("WATCHDOG_INTVAL_JF:%u, USER_OFFLINE_JF:%u, USER_TIMEOUT_JF:%u\n",
				s_watchdog_intval_jf, s_user_off_intval_jf, s_user_timeout_intval_jf);
	AUTH_INFO("auth_user_init success.\n");
	return 0;
}


int auth_user_fini(void)
{
	spin_lock_bh(&s_user_hash.lock);
	OS_CANCEL_TIMER(&s_watchdog_tm);
	auth_user_clear();
	spin_unlock_bh(&s_user_hash.lock);
	AUTH_INFO("auth_user_fini success.\n");
	return 0;
}