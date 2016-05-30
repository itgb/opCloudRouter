#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/seq_file.h>
#include <linux/export.h>

#include "auth_ioc.h"
#include "auth_config.h"
#include "auth_rule.h"

static int s_auth_major = 0;
static int s_auth_minor = 0;
static int s_n_dev =1;
static struct cdev s_auth_cdev;
const char *s_auth_dev_name = "auth_user_info";
static struct class *s_auth_class = NULL;
static struct device *s_auth_dev = NULL;

static DEFINE_MUTEX(s_auth_dev_mutex);
//s_user_hash.user_lock =  __RW_LOCK_UNLOCKED(s_user_hash.user_lock);
//static spinlock_t s_auth_cdev_lock;


// static void *auth_start(struct seq_file *m, loff_t *pos)
// __acquires(&s_auth_cdev_lock)
// {
// 	spin_lock_bh(&s_auth_cdev_lock);
// 	return NULL;
// }

// static void *auth_next(struct seq_file *m, void *v, loff_t *pos)
// {
// 	return NULL;
// }

// static void auth_stop(struct seq_file *m, void *v)
// __releases(&s_auth_cdev_lock)
// {
// 	spin_unlock_bh(&s_auth_cdev_lock);
// }

// static int auth_show(struct seq_file *m, void *v)
// {
// 	seq_printf(m, "auth show.\n");
// 	return 0;
// }


// const struct seq_operations auth_seq_ops = {
// 	.start = auth_start,
// 	.next = auth_next,
// 	.stop = auth_stop,
// 	.show = auth_show,
// };


// static int auth_open(struct inode *inode, struct file *file)
// {
// 	printk(KERN_ALERT "auth_open\n");
// 	return seq_open(file, &auth_seq_ops);
// }


// static int auth_release(struct inode *inode, struct file *file)
// {
// 	printk(KERN_ALERT "auth_release\n");
// 	return seq_release(inode, file);
// }


// static ssize_t auth_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
// {
// 	printk(KERN_ALERT "auth_read\n");
// 	return seq_read(file, buf, buf_len, offset);
// }


/*unlocked ioctl, need lock by self*/
static long auth_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0, total_len = 0, need_enable = 0;
	struct auth_ioc_arg arg_hdr, *auth_arg = NULL;

	mutex_lock(&s_auth_dev_mutex);
	if (get_auth_cfg_status() == AUTH_CONF_AVAILABLE) {
		auth_cfg_disable();
		need_enable = 1;
	}
	if (copy_from_user((void*)&arg_hdr, (void*)arg, sizeof(struct auth_ioc_arg))) {
		ret = -1;
		goto OUT;
	}
	total_len = sizeof(struct auth_ioc_arg) + arg_hdr.data_len;
	auth_arg = AUTH_NEW_MEM(total_len);
	if (auth_arg == NULL) {
		ret = -1;
		goto OUT;
	}
	if (copy_from_user((void*)auth_arg, (void*)arg, total_len)) {
		ret = -1;
		goto OUT;
	}
	
	switch(cmd) {
		case SIOCSUSRSTAT:
			ret = do_set_auth_user_stat(auth_arg);
			break;

		case SIOCSAUTHRULES:
			ret = do_set_auth_rules(auth_arg);	
			break;

		case SIOCGUSRSTAT:
			ret = do_get_auth_user_stat(auth_arg);
			break;

		case SIOCSAUTHOPTIONS:
			ret = do_set_auth_options(auth_arg);
			break;

		case SIOCSIFINFO:
			ret = do_set_auth_ifinfo(auth_arg);
			break;
		case SIOCSAUTHURLS:
			ret = do_set_auth_urlinfo(auth_arg);
			break;

		case SIOCSDEBUGOPTIONS:
			ret = do_set_debug_options(auth_arg);
			break;
			
		default:
			ret = -1;
			break;
	}
OUT:
	if (auth_arg) {
		kfree(auth_arg);
	}
	if (need_enable) {
		auth_cfg_enable();
	}
	mutex_unlock(&s_auth_dev_mutex);
	return ret; 
}

static struct file_operations auth_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = auth_unlocked_ioctl,
};


int dev_init(void) { 
	int retval = 0;
	dev_t devno;

	if (s_auth_major>0) {
		devno = MKDEV(s_auth_major, s_auth_minor);
		retval = register_chrdev_region(devno, s_n_dev, s_auth_dev_name);
	} 
	else {
		retval = alloc_chrdev_region(&devno, s_auth_minor, s_n_dev, s_auth_dev_name);
	}

	if (retval < 0) {
		AUTH_ERROR("auth: alloc_chrdev_region failed.\n");
		return retval;
	}
	s_auth_major = MAJOR(devno);
	s_auth_minor = MINOR(devno);
	AUTH_INFO("s_auth_major=%d, s_auth_minor=%d.\n", s_auth_major, s_auth_minor);

	cdev_init(&s_auth_cdev, &auth_fops);
	s_auth_cdev.owner = THIS_MODULE;
	s_auth_cdev.ops = &auth_fops;

	retval = cdev_add(&s_auth_cdev, devno, 1);
	if (retval) {
		AUTH_ERROR(KERN_NOTICE "error=%d adding chardev.\n", retval);
		goto cdev_add_failed;
	}

	s_auth_class = class_create(THIS_MODULE,"s_auth_class");
	if (IS_ERR(s_auth_class)) {
		AUTH_ERROR("failed in creating class.\n");
		retval = -EINVAL;
		goto class_create_failed;
	}

	s_auth_dev = device_create(s_auth_class, NULL, devno, NULL, s_auth_dev_name);
	if (!s_auth_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	AUTH_INFO("auth dev_init success.\n");
	return 0; 

device_create_failed:
	class_destroy(s_auth_class);
class_create_failed:
	cdev_del(&s_auth_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, s_n_dev);
	AUTH_ERROR("auth dev_init failed.\n");
	return retval;
}


void  dev_fini(void) {
	dev_t devno;
	mutex_lock(&s_auth_dev_mutex);
	devno = MKDEV(s_auth_major, s_auth_minor);
	device_destroy(s_auth_class, devno);
	class_destroy(s_auth_class);
	cdev_del(&s_auth_cdev);
	unregister_chrdev_region(devno, s_n_dev);
	mutex_unlock(&s_auth_dev_mutex);
	AUTH_INFO("dev_fini success.\n");
	return;
}

