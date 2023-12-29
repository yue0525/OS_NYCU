/* 
 * chardev.c: Creates a read-only char device that says how many times 
 * you have read from the dev file 
 */
#include <linux/jiffies.h>
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h> /* for sprintf() */
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h> /* for get_user and put_user */
#include <linux/version.h>
#include <asm/errno.h>
#include <linux/utsname.h>
#include <linux/sysinfo.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <asm/processor.h>
#include <linux/cpu.h>
#include <linux/sched/signal.h>
#include <linux/smp.h>
#include <linux/cpumask.h>

#define SUCCESS 0
#define DEVICE_NAME "kfetch_mod_311552055"

#define BUF_LEN 3000
static int kfetch_open(struct inode *, struct file *);
static int kfetch_release(struct inode *, struct file *);
static ssize_t kfetch_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t kfetch_write(struct file *, const char __user *, size_t,
			    loff_t *);

static int major;

enum {
	CDEV_NOT_USED = 0,
	CDEV_EXCLUSIVE_OPEN = 1,
};

static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

static char msg[BUF_LEN + 1];

static struct class *cls;

static int current_mask = 0;

static int mask_num[6] = { 1, 1, 1, 1, 1, 1 };
char dash[200];
char Kernel_buf[200];
char CPU_buf[100];
char CPUs_buf[200];
char Mem_buf[100];
char Procs_buf[100];
char Uptime_buf[100];
char penguin0[100] = "                   ";
char penguin1[100] = "        .-.        ";
char penguin2[100] = "       (.. |       ";
char penguin3[100] = "       <>  |       ";
char penguin4[100] = "      / --- \\      ";
char penguin5[100] = "     ( |   | |     ";
char penguin6[100] = "   |\\\\_)___/\\)/\\   ";
char penguin7[100] = "  <__)------(__/   ";

static const char *get_cpu_model_name(void)
{
	return boot_cpu_data.x86_model_id;
}

static int count_processes(void)
{
	struct task_struct *task;
	int count = 0;

	rcu_read_lock();
	for_each_process(task) {
		count++;
	}
	rcu_read_unlock();

	return count;
}

const static struct file_operations kfetch_ops = {
	.read = kfetch_read,
	.write = kfetch_write,
	.open = kfetch_open,
	.release = kfetch_release,
};

static int __init kfetch_init(void)
{
	major = register_chrdev(0, DEVICE_NAME, &kfetch_ops);

	if (major < 0) {
		pr_alert("Registering char device failed with %d\n", major);
		return major;
	}

	pr_info("I was assigned major number %d.\n", major);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	cls = class_create(DEVICE_NAME);
#else
	cls = class_create(THIS_MODULE, DEVICE_NAME);
#endif
	device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

	pr_info("Device created on /dev/%s\n", DEVICE_NAME);

	return SUCCESS;
}

static void __exit kfetch_exit(void)
{
	device_destroy(cls, MKDEV(major, 0));
	class_destroy(cls);
	unregister_chrdev(major, DEVICE_NAME);
}

static ssize_t kfetch_read(struct file *filp, char __user *buffer,
			   size_t length, loff_t *offset)
{
	int bytes_read = 0;

	static int mask_temp[6];
	for (int i = 0; i < 6; i++) {
		mask_temp[i] = mask_num[i];
	}
	/*for kernel info*/
	struct sysinfo i;
	unsigned long uptime;
	si_meminfo(&i);

	uptime = jiffies_to_msecs(jiffies) / 1000; //for boot time
	sprintf(Kernel_buf, "Kernel:  %s", init_utsname()->release);
	sprintf(CPU_buf, "CPU:  %s", get_cpu_model_name());
	sprintf(CPUs_buf, "CPUs: %d / %d", num_online_cpus(),
		num_possible_cpus());
	sprintf(Mem_buf, "Mem: %lu / %lu MB", i.freeram * 4 / 1024,
		i.totalram * 4 / 1024);
	unsigned int num_procs = count_processes();
	sprintf(Procs_buf, "Procs:  %d", num_procs);
	sprintf(Uptime_buf, "Uptime: %lu mins", uptime / 60);
	pr_info("Kernel:  %s", init_utsname()->release);

	sprintf(msg + strlen(msg), "%s", penguin0);
	sprintf(msg + strlen(msg), "%s\n", utsname()->nodename);
	sprintf(msg + strlen(msg), "%s", penguin1);

	char *hostname = init_utsname()->nodename;
	int len_name = 0;
	while (len_name < __NEW_UTS_LEN && hostname[len_name] != '\0') {
		len_name++;
	}
	memset(dash, '-', len_name);

	sprintf(msg + strlen(msg), "%s\n", dash);

	for (int i = 0; i < 6; i++) {
		if (i == 0) {
			sprintf(msg + strlen(msg), "%s", penguin2);
		}
		if (i == 1) {
			sprintf(msg + strlen(msg), "%s", penguin3);
		}
		if (i == 2) {
			sprintf(msg + strlen(msg), "%s", penguin4);
		}
		if (i == 3) {
			sprintf(msg + strlen(msg), "%s", penguin5);
		}
		if (i == 4) {
			sprintf(msg + strlen(msg), "%s", penguin6);
		}
		if (i == 5) {
			sprintf(msg + strlen(msg), "%s", penguin7);
		}
		for (int j = 0; j < 6; j++) {
			if (mask_temp[j] == 1) {
				if (j == 0) {
					sprintf(msg + strlen(msg), Kernel_buf);
					mask_temp[j] = 0;
					break;
				}
				if (j == 1) {
					sprintf(msg + strlen(msg), CPUs_buf);
					mask_temp[j] = 0;
					break;
				}
				if (j == 2) {
					sprintf(msg + strlen(msg), CPU_buf);
					mask_temp[j] = 0;
					break;
				}
				if (j == 3) {
					sprintf(msg + strlen(msg), Mem_buf);
					mask_temp[j] = 0;
					break;
				}
				if (j == 4) {
					sprintf(msg + strlen(msg), Uptime_buf);
					mask_temp[j] = 0;
					break;
				}
				if (j == 5) {
					sprintf(msg + strlen(msg), Procs_buf);
					mask_temp[j] = 0;
					break;
				}
			}
		}
		sprintf(msg + strlen(msg), "\n");
	}

	const char *msg_ptr = msg;

	if (!*(msg_ptr)) {
		*offset = 0;
		return 0;
	}

	// msg_ptr += *offset;

	while (*msg_ptr) {
		put_user(*(msg_ptr++), buffer++);
		bytes_read++;
	}
	memset(msg, 0, sizeof(msg));
	*offset += bytes_read;
	return bytes_read;
}

static ssize_t kfetch_write(struct file *filp, const char __user *buffer,
			    size_t length, loff_t *offset)
{
	static int mask_info;
	// static int mask_num[6];

	if (length != sizeof(mask_info)) {
		return -EINVAL;
	}

	// current_mask = mask_info;
	if (copy_from_user(&mask_info, buffer, sizeof(mask_info))) {
		pr_alert("Failed to copy data from user");
		return -EFAULT;
	}

	for (int i = 0; i < 6; i++) {
		mask_num[i] = 1;
		if (!(mask_info & (1 << i))) {
			// sprintf(msg + strlen(msg), "%d", i);
			mask_num[i] = 0;
		}
	}

	pr_info("kfetch: New mask set: 0x%x\n", current_mask);
	return sizeof(mask_info);
}

static int kfetch_open(struct inode *inode, struct file *file)
{
	if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN) ==
	    CDEV_EXCLUSIVE_OPEN) {
		return -EBUSY;
	}

	try_module_get(THIS_MODULE);
	return SUCCESS;
}

static int kfetch_release(struct inode *inode, struct file *file)
{
	atomic_set(&already_open, CDEV_NOT_USED);
	module_put(THIS_MODULE);

	return SUCCESS;
}

module_init(kfetch_init);
module_exit(kfetch_exit);
MODULE_LICENSE("GPL");