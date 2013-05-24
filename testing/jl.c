#include <linux/kernel.h>
#include <linux/jump_label.h>
#include <linux/module.h>

struct jump_label_key jl_a = JUMP_LABEL_INIT;
struct jump_label_key jl_b = JUMP_LABEL_INIT;

int jl_init(void)
{
	jump_label_inc(&jl_a);
	jump_label_inc(&jl_a);
	return 0;
}

void jl_exit(void)
{
	unsigned int i;
	unsigned long j;
	unsigned long start, end;

	j = 0;
	start = jiffies;
	for (i = 0; i < 900000000; i++) {
		if (static_branch(&jl_a)) {
			j += start - 1;
		} else
			j += start;
	}
	end = jiffies;
	printk("a1. d=%lu j=%lu\n", end-start, j);

	j = 0;
	start = jiffies;
	for (i = 0; i < 900000000; i++) {
		if (start)
			j += start - 1;
		else
			j += start;
	}
	end = jiffies;
	printk("a2. d=%lu j=%lu\n", end-start, j);

	j = 0;
	start = jiffies;
	for (i = 0; i < 900000000; i++) {
		if (static_branch(&jl_b)) {
			j += start - 1;
		} else
			j += start;
	}
	end = jiffies;
	printk("b1. d=%lu j=%lu\n", end-start, j);

	j = 0;
	start = jiffies;
	for (i = 0; i < 900000000; i++) {
		if (start)
			j += start - 1;
		else
			j += start;
	}
	end = jiffies;
	printk("b2. d=%lu j=%lu\n", end-start, j);

}

module_init(jl_init);
module_exit(jl_exit);
MODULE_LICENSE("GPL");
