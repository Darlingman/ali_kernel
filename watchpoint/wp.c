#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <asm/processor.h>
#include <linux/kdebug.h>

#define DR7_BPn_SW_MASK(n)	(0x3UL << (2*n))
#define DR7_GLBPn_ENABLE(n)	(0x3UL << (2*n))
#define DR7_GBPn_ENABLE(n)	(0x2UL << (2*n))
#define DR7_LBPn_ENABLE(n)	(0x1UL << (2*n))
#define DR7_BPn_DISABLE(n)	(0x0UL << (2*n))
#define DR7_RESERVED		(0x1UL << 10)

#define DR7_GE_LE		(0x3UL << 8)
#define DR7_GD			(0x1UL << 13)

#define DR7_BPn_MEM(n)		(0x3UL << ((4*n) + 16))
#define DR7_BPn_IO(n)		(0x2UL << ((4*n) + 16))
#define DR7_BPn_WR(n)		(0x1UL << ((4*n) + 16))
#define DR7_BPn_INST(n)		(0x0UL << ((4*n) + 16))

#define DR7_BPn_LEN1(n)		(0x0UL << ((4*n) + 18))
#define DR7_BPn_LEN2(n)		(0x1UL << ((4*n) + 18))
#define DR7_BPn_LEN8(n)		(0x2UL << ((4*n) + 18))
#define DR7_BPn_LEN4(n)		(0x3UL << ((4*n) + 18))

#define DR6_BPn_HIT(n)		(1UL << (n))
#define DR6_BD			(1UL << 13)	//BD (debug register access detected) flag
#define DR6_BS			(1UL << 14)	//BS (single step) flag
#define DR6_BT			(1UL << 15)	//BT (task switch) flag


#define MAX_NR_CPUS	128
#define MAX_BP		4
static void (*p_show_regs)(struct pt_regs *regs, int all);

struct watchpoint {
	void *addr;
	int len;
	unsigned int mem : 1;
	unsigned int mem_write : 1;
	unsigned int exec : 1;
	unsigned int io : 1;
	unsigned int gd : 1;
	int bp[MAX_NR_CPUS];
	int error[MAX_NR_CPUS];
};

static unsigned long wp_get_debugreg(int no)
{
	unsigned long v;

	get_debugreg(v, no);
	return v;
}

static void wp_set_debugreg(int no, unsigned long v)
{
	set_debugreg(v, no);
}

static void __clean_watchpoint(void *arg)
{
	struct watchpoint *wp = (struct watchpoint *)arg;
	unsigned long dr7, addr;
	int bp, cpu = smp_processor_id();

	bp = wp->bp[cpu] - 1;

	if (bp >= 0 && bp <= 3) {
		dr7 = wp_get_debugreg(7);
		printk("before clean: cpu%d.dr7 = %016lx\n", cpu, dr7);
		addr = wp_get_debugreg(bp);
		printk("before clean: cpu%d.dr%d = %016lx\n", cpu, bp, addr);

		dr7 &= ~DR7_BPn_SW_MASK(bp);
		wp_set_debugreg(bp, 0UL);
		wp_set_debugreg(7, dr7);

		wp->bp[cpu] = 0;
	}
}

static void clean_watchpoint(struct watchpoint *wp)
{
	on_each_cpu(__clean_watchpoint, wp, 1);
}

static void __setup_watchpoint(void *arg)
{
	struct watchpoint *wp = (struct watchpoint *)arg;
	unsigned long dr7;
	unsigned long bp_sw, bp_type, bp_len, bp_gd;
	int bp, cpu = smp_processor_id();

	dr7 = wp_get_debugreg(7);

	/* allocate a breakpoint */
	for (bp = 0; bp < MAX_BP; bp++) {
		if (DR7_BPn_DISABLE(bp) == (dr7 & DR7_BPn_SW_MASK(bp)))
			break;
	}
	if (bp >= MAX_BP) {
		printk("setup_watchpoint(): busy error, cpu%d.dr7=%lx\n", cpu, dr7);
		wp->error[cpu] = -EBUSY;
		return;
	}
	bp_sw = DR7_GBPn_ENABLE(bp);

	if (wp->mem)
		bp_type = DR7_BPn_MEM(bp);
	else if (wp->mem_write)
		bp_type = DR7_BPn_WR(bp);
	else if (wp->io)
		bp_type = DR7_BPn_IO(bp);
	else if (wp->exec)
		bp_type = DR7_BPn_INST(bp);
	else {
		wp->error[cpu] = -EINVAL;
		return;
	}

	switch (wp->len) {
	case 1:
		bp_len = DR7_BPn_LEN1(bp); break;
	case 2:
		bp_len = DR7_BPn_LEN2(bp); break;
	case 4:
		bp_len = DR7_BPn_LEN4(bp); break;
	case 8:
		bp_len = DR7_BPn_LEN8(bp); break;
	default:
		wp->error[cpu] = -EINVAL;
		return;
	}

	bp_gd = wp->gd ? DR7_GD : 0;

	wp_set_debugreg(bp, (unsigned long)wp->addr);
	dr7 = bp_len | bp_type | bp_gd | DR7_GE_LE | DR7_RESERVED | bp_sw;
	wp_set_debugreg(7, dr7);

	dr7 = wp_get_debugreg(7);
	printk("bp len=%lx type=%lx gd=%lx sw=%lx\n", bp_len, bp_type, bp_gd, bp_sw);

	printk("after  setup: cpu%d.dr7 = %016lx\n", cpu, dr7);
	printk("after  setup: cpu%d.dr%d = %016lx\n",
			cpu, bp, wp_get_debugreg(bp));

	wp->bp[cpu] = bp + 1;
	wp->error[cpu] = 0;
}

static int setup_watchpoint(struct watchpoint *wp)
{
	int cpu;

	on_each_cpu(__setup_watchpoint, wp, 1);
	for_each_online_cpu(cpu) {
		if (cpu < MAX_NR_CPUS && wp->error[cpu] < 0) {
			printk("wp 0x%p cpu%d error=%d\n",
				wp, cpu, wp->error[cpu]);
			clean_watchpoint(wp);
			return wp->error[cpu];
		}
	}
	return 0;
}

static int do_debug(struct notifier_block *nb, unsigned long die, void *void_args)
{
	struct die_args *args = (struct die_args *)void_args;
	unsigned long dr6;

	if (DIE_DEBUG != die)
		return NOTIFY_DONE;

	dr6 = args->err;

	printk("bp0=%d bp1=%d bp2=%d bp3=%d BD=%d BS=%d BT=%d\n",
		!!(DR6_BPn_HIT(0) & dr6),
		!!(DR6_BPn_HIT(1) & dr6),
		!!(DR6_BPn_HIT(2) & dr6),
		!!(DR6_BPn_HIT(3) & dr6),
		!!(DR6_BD & dr6),
		!!(DR6_BS & dr6),
		!!(DR6_BT & dr6));

	if ((DR6_BD & dr6)) {
		return NOTIFY_STOP;
	}

	p_show_regs(args->regs, 1);
	return NOTIFY_STOP;
}

static struct notifier_block debug_hook = {
	.notifier_call = do_debug,
};


static void *ali_get_symbol_address(const char *name)
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
	/* for old kernel, this function is not exported */
	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	register_kprobe(&kp);
	unregister_kprobe(&kp);
	if (!kp.addr)
		return NULL;

	kallsyms_lookup_name = (void *)kp.addr;
	return (void *)kallsyms_lookup_name(name);
}

static void wp_exit(void);

unsigned int v;

struct watchpoint wp = {
	.addr = &v,
	.len = 4,
	.mem = 1,
};

static noinline void set_v(unsigned int *p)
{
	*p = 0x87654321;
}

static int __init wp_init(void)
{
	p_show_regs = ali_get_symbol_address("__show_regs");
	if (!p_show_regs)
		return -EINVAL;

	if (register_die_notifier(&debug_hook))
		return -EINVAL;
	setup_watchpoint(&wp);
	v = 0x12345678;
	set_v(&v);
	printk("v = %p/%x\n", &v, *(&v));
	clean_watchpoint(&wp);
	return 0;
}

static void wp_exit(void)
{
	unregister_die_notifier(&debug_hook);
}

module_init(wp_init);
module_exit(wp_exit);
MODULE_LICENSE("GPL");
