#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <asm/asm-offsets.h>
#include <asm/unistd.h>

#define MAGIC 0xAFCCB99C
#define VERSION	1

#define MAX_SYSCALL_PAGE	(PAGE_SIZE << 2)

#ifndef DEBUG
#define DEBUG 0
#endif

struct syscall_entry {
	long op;
	long ret;
	long args[6];
};

struct syscall_page_header {
	unsigned long magic;
	unsigned long version;
	unsigned long nr_syscalls;
	unsigned long nr_completed;
	unsigned long flags;
	unsigned long reserved[3];
	struct syscall_entry entries[0];
};

static struct syscall_page_header zero_scp_header = {
	.magic = MAGIC,
	.version = VERSION,
};

static int copy_zero_scp_header(char __user *buf, size_t count)
{
	if (count < sizeof(struct syscall_page_header))
		return -EINVAL;
	if (copy_to_user(buf, &zero_scp_header, count))
		return -EFAULT;
	return count;
}

typedef asmlinkage int (*syscall_kfunc)(unsigned long, unsigned long,
				unsigned long, unsigned long,
				unsigned long, unsigned long);

struct batch_accept4_arg;
struct batch_epoll_ctl_arg;
int asmlinkage batch_accept4(int fd, struct batch_accept4_arg *args, int *total, int flags);
int asmlinkage batch_epoll_ctl(int epfd, struct batch_epoll_ctl_arg *args, int *total);

#define DEFINE_SYSCALL_KFUNC(name)	static syscall_kfunc *p_sys_##name

#define LOAD_SYSCALL_KFUNC(name)	\
	p_sys_##name = get_symbol_address("sys_"#name);\
	if (!p_sys_##name)\
		return #name;

DEFINE_SYSCALL_KFUNC(sendmsg);
DEFINE_SYSCALL_KFUNC(sendmmsg);
DEFINE_SYSCALL_KFUNC(sendto);
DEFINE_SYSCALL_KFUNC(write);
DEFINE_SYSCALL_KFUNC(pwrite64);
DEFINE_SYSCALL_KFUNC(writev);
DEFINE_SYSCALL_KFUNC(recvmmsg);
DEFINE_SYSCALL_KFUNC(recvmsg);
DEFINE_SYSCALL_KFUNC(recvfrom);
DEFINE_SYSCALL_KFUNC(read);
DEFINE_SYSCALL_KFUNC(pread64);
DEFINE_SYSCALL_KFUNC(readv);
DEFINE_SYSCALL_KFUNC(socket);
DEFINE_SYSCALL_KFUNC(setsockopt);
DEFINE_SYSCALL_KFUNC(getsockopt);
DEFINE_SYSCALL_KFUNC(accept);
DEFINE_SYSCALL_KFUNC(close);
DEFINE_SYSCALL_KFUNC(epoll_ctl);
DEFINE_SYSCALL_KFUNC(ioctl);
DEFINE_SYSCALL_KFUNC(splice);
DEFINE_SYSCALL_KFUNC(vmsplice);
DEFINE_SYSCALL_KFUNC(sendfile);
DEFINE_SYSCALL_KFUNC(epoll_create);
DEFINE_SYSCALL_KFUNC(getpid);

#define SETUP_SYSCALL_KFUNC(name)	\
	[__NR_##name] = {\
		.p_kfunc	=	(syscall_kfunc*)&p_sys_##name,\
		.str		=	#name,\
	}

struct syscall_list {
	syscall_kfunc *p_kfunc;
	syscall_kfunc kfunc;
	const char *str;
};

#define EMPTY_SYSCALL_SLOT \
	{\
		.p_kfunc = NULL,\
		.kfunc = (syscall_kfunc)NULL,\
		.str = NULL,\
	}

static struct syscall_list syscalls_list[NR_syscalls] = {
	SETUP_SYSCALL_KFUNC(sendmsg),
	SETUP_SYSCALL_KFUNC(sendmmsg),
	SETUP_SYSCALL_KFUNC(sendto),
	SETUP_SYSCALL_KFUNC(write),
	SETUP_SYSCALL_KFUNC(pwrite64),
	SETUP_SYSCALL_KFUNC(writev),
	SETUP_SYSCALL_KFUNC(recvmmsg),
	SETUP_SYSCALL_KFUNC(recvmsg),
	SETUP_SYSCALL_KFUNC(recvfrom),
	SETUP_SYSCALL_KFUNC(read),
	SETUP_SYSCALL_KFUNC(pread64),
	SETUP_SYSCALL_KFUNC(readv),
	SETUP_SYSCALL_KFUNC(socket),
	SETUP_SYSCALL_KFUNC(setsockopt),
	SETUP_SYSCALL_KFUNC(getsockopt),
	SETUP_SYSCALL_KFUNC(accept),
	SETUP_SYSCALL_KFUNC(close),
	SETUP_SYSCALL_KFUNC(epoll_ctl),
	SETUP_SYSCALL_KFUNC(ioctl),
	SETUP_SYSCALL_KFUNC(splice),
	SETUP_SYSCALL_KFUNC(vmsplice),
	SETUP_SYSCALL_KFUNC(sendfile),
	SETUP_SYSCALL_KFUNC(epoll_create),
	SETUP_SYSCALL_KFUNC(getpid),
};

#define __NR_batch_epoll_ctl	1
#define __NR_batch_accept4	2
#define NR_batch_syscalls	(__NR_batch_accept4 + 1)

#define SETUP_BATCH_SYSCALL_KFUNC(name)	\
	[__NR_batch_##name] = {\
		.kfunc	=	(syscall_kfunc)batch_##name,\
		.str	=	"batch_" #name,\
	}

static struct syscall_list batch_syscalls_list[NR_batch_syscalls] = {
	EMPTY_SYSCALL_SLOT,
	SETUP_BATCH_SYSCALL_KFUNC(epoll_ctl),
	SETUP_BATCH_SYSCALL_KFUNC(accept4),
};

static void batch_syscall(struct syscall_page_header *scp)
{
	long i;

	scp->nr_completed = 0;
	for (i = 0; i < scp->nr_syscalls; i++) {
		struct syscall_list *sc_list;
		syscall_kfunc syscall;
		const char *str;
		long op;

		op = scp->entries[i].op;

		if (op >= 0) {
			if (op >= NR_syscalls) {
				scp->entries[i].ret = -EINVAL;
				goto next;
			}
			sc_list = syscalls_list;
		} else {
			op = -op;
			if (op >= NR_batch_syscalls) {
				scp->entries[i].ret = -EINVAL;
				goto next;
			}
			sc_list = batch_syscalls_list;
		}

		syscall = sc_list[op].kfunc;
		if (!syscall) {
			if (!sc_list[op].p_kfunc) {
				scp->entries[i].ret = -EINVAL;
				goto next;
			}
			syscall = *sc_list[op].p_kfunc;
			sc_list[op].kfunc = syscall;
		}

		str = sc_list[op].str;
		scp->entries[i].ret = syscall(scp->entries[i].args[0],
					scp->entries[i].args[1],
					scp->entries[i].args[2],
					scp->entries[i].args[3],
					scp->entries[i].args[4],
					scp->entries[i].args[5]);
		next:
		scp->nr_completed++;
#if DEBUG > 0
		printk("%p op=%ld %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = %ld\n",
				syscall,
				scp->entries[i].op,
				str,
				scp->entries[i].args[0],
				scp->entries[i].args[1],
				scp->entries[i].args[2],
				scp->entries[i].args[3],
				scp->entries[i].args[4],
				scp->entries[i].args[5],
				scp->entries[i].ret);
#endif
	}
}

static ssize_t syscall_batcher_read(struct file *file, char __user *buf,
						size_t count, loff_t *ppos)
{
	return copy_zero_scp_header(buf, count);
}

static int validate_scp_header(struct syscall_page_header *h, size_t count)
{
	size_t bytes;

	if (MAGIC != h->magic || VERSION != h->version) {
		return -EINVAL;
	}
	bytes = h->nr_syscalls * sizeof(struct syscall_entry);
	bytes += sizeof(struct syscall_page_header);
	if (count != bytes || count > MAX_SYSCALL_PAGE) {
		return -EINVAL;
	}
	if (h->flags || h->reserved[0] || h->reserved[1] || h->reserved[2]) {
		return -EINVAL;
	}
	return 0;
}

static ssize_t syscall_batcher_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	size_t ret;
	struct syscall_page_header scp_header, *scp = file->private_data;

	if (scp->nr_completed != scp->nr_syscalls)
		return -EBUSY;

	if (copy_from_user(&scp_header, buf, sizeof(scp_header)))
		return -EFAULT;
	ret = validate_scp_header(&scp_header, count);
	if (ret)
		return ret;

	if (copy_from_user(scp, buf, count))
		return -EFAULT;

	batch_syscall(scp);

	if (copy_to_user((char*)buf, scp, count))
		return -EFAULT;

	return count;
}

static int syscall_batcher_open(struct inode *inode, struct file *file)
{
	file->private_data = kzalloc(MAX_SYSCALL_PAGE, GFP_KERNEL);
	if (!file->private_data)
		return -ENOMEM;
	return nonseekable_open(inode, file);
}

static int syscall_batcher_close(struct inode *inode, struct file *file)
{
	struct syscall_page_header *scp;

	scp = file->private_data;
	if (scp)
		kfree(scp);
	file->private_data = NULL;
	return 0;
}

static const struct file_operations syscall_batcher_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.write = syscall_batcher_write,
	.read = syscall_batcher_read,
	.open = syscall_batcher_open,
	.release = syscall_batcher_close,
};

static struct miscdevice syscall_batcher_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "syscall-batcher",
	.fops = &syscall_batcher_fops,
};

/* A tricky usage of kprobe ;) */
static void *get_symbol_address(const char *name)
{
        struct kprobe kp;
	unsigned long (*kallsyms_lookup_name)(const char *name);

	/* for symbols in text sections */
        memset(&kp, 0, sizeof(kp));
        kp.symbol_name = name;
        register_kprobe(&kp);
        unregister_kprobe(&kp);

 	if (kp.addr)
		return kp.addr;

	/* for symbols in data sections */
        memset(&kp, 0, sizeof(kp));
        kp.symbol_name = "kallsyms_lookup_name";
        register_kprobe(&kp);
        unregister_kprobe(&kp);
	if (!kp.addr)
		return NULL;

	kallsyms_lookup_name = (void*)kp.addr;
	return (void*)kallsyms_lookup_name(name);
}

static char* load_syscall_symbols(void)
{
	LOAD_SYSCALL_KFUNC(sendmsg);
	LOAD_SYSCALL_KFUNC(sendmmsg);
	LOAD_SYSCALL_KFUNC(sendto);
	LOAD_SYSCALL_KFUNC(write);
	LOAD_SYSCALL_KFUNC(pwrite64);
	LOAD_SYSCALL_KFUNC(writev);
	LOAD_SYSCALL_KFUNC(recvmmsg);
	LOAD_SYSCALL_KFUNC(recvmsg);
	LOAD_SYSCALL_KFUNC(recvfrom);
	LOAD_SYSCALL_KFUNC(read);
	LOAD_SYSCALL_KFUNC(pread64);
	LOAD_SYSCALL_KFUNC(readv);
	LOAD_SYSCALL_KFUNC(socket);
	LOAD_SYSCALL_KFUNC(setsockopt);
	LOAD_SYSCALL_KFUNC(getsockopt);
	LOAD_SYSCALL_KFUNC(accept);
	LOAD_SYSCALL_KFUNC(close);
	LOAD_SYSCALL_KFUNC(epoll_ctl);
	LOAD_SYSCALL_KFUNC(ioctl);
	LOAD_SYSCALL_KFUNC(splice);
	LOAD_SYSCALL_KFUNC(vmsplice);
	LOAD_SYSCALL_KFUNC(sendfile);
	LOAD_SYSCALL_KFUNC(epoll_create);
	LOAD_SYSCALL_KFUNC(getpid);

	return NULL;
}

static int __init syscall_batcher_init(void)
{
	int res;
	char *string;

	string = load_syscall_symbols();
	if (string) {
		printk(KERN_ERR "failed to lookup symbol %s\n", string);
		return -EINVAL;
	}

	res = misc_register(&syscall_batcher_miscdev);
	if (res) {
		printk(KERN_ERR "failed to register misc device\n");
		return res;
	}

	return 0;
}

static void __exit syscall_batcher_exit(void)
{
	misc_deregister(&syscall_batcher_miscdev);
}

module_init(syscall_batcher_init);
module_exit(syscall_batcher_exit);

MODULE_AUTHOR("Li Yu <bingtian.ly@taobao.com>");
MODULE_DESCRIPTION("A stupid syscall batcher");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
