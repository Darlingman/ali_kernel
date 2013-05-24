/*
 *  skbtrace - sk_buff trace utilty
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * 2012 Li Yu <bingtian.ly@taobao.com>
 *
 */

#include <linux/module.h>
#include <linux/relay.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/jhash.h>

#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/skbtrace.h>
#include <net/sock.h>

#define SKBTRACE_VERSION	"1"
#define SKBTRACE_DIR		"skbtrace"

static unsigned long skbtrace_dropped[NR_CHANNELS][NR_CPUS];
/* +1 for quick indexing trick in __skbtrace_probe() */
static struct rchan *skbtrace_channels[NR_CHANNELS + 1];

int sysctl_skbtrace_filter_default = 0;
EXPORT_SYMBOL_GPL(sysctl_skbtrace_filter_default);
static struct sk_buff **sock_filter_skb;
static struct sock_fprog skb_filter_fprog;
static struct sock_fprog sock_filter_fprog;
struct sk_filter *skbtrace_skb_filter;
EXPORT_SYMBOL_GPL(skbtrace_skb_filter);

u32 skbtrace_sock_filter_id;
EXPORT_SYMBOL_GPL(skbtrace_sock_filter_id);
struct sk_filter *skbtrace_sock_filter;
EXPORT_SYMBOL_GPL(skbtrace_sock_filter);

static struct dentry	*skbtrace_dentry;
static struct dentry	*enabled_control;
static struct dentry	*dropped_control;
static struct dentry	*version_control;
static struct dentry	*subbuf_nr_control;
static struct dentry	*subbuf_size_control;
static struct dentry	*filters_control;
static struct dentry	*sock_filters_control;

static const struct file_operations	enabled_fops;
static const struct file_operations	dropped_fops;
static const struct file_operations	version_fops;
static const struct file_operations	subbuf_nr_fops;
static const struct file_operations	subbuf_size_fops;
static const struct file_operations	filters_fops;
static const struct file_operations	sock_filters_fops;

static int nr_skbtrace_enabled_tp;
static int subbuf_nr = SKBTRACE_DEF_SUBBUF_NR;
static int subbuf_size = SKBTRACE_DEF_SUBBUF_SIZE;

static bool should_load_proto;

struct jump_label_key skbtrace_filters_enabled = JUMP_LABEL_INIT;
EXPORT_SYMBOL_GPL(skbtrace_filters_enabled);

atomic64_t skbtrace_event_seq = ATOMIC64_INIT(0);
EXPORT_SYMBOL_GPL(skbtrace_event_seq);

/* protect agaist af_tp_list and skbtrace_channels */
static struct mutex skbtrace_lock;
static struct skbtrace_tracepoint *af_tp_list[AF_MAX];
struct skbtrace_ops* skbtrace_ops[AF_MAX];

static int create_controls(void);
static void remove_controls(void);
static int  create_channels(void);
static void flush_channels(void);
static void destroy_channels(void);
static ssize_t sk_filter_read(struct sock_fprog *fprog, char __user *buffer,
							    size_t count);
static ssize_t sk_filter_write(struct sock_fprog *sk_fprog,
				struct sk_filter **sk_filter,
				const char __user *buffer, size_t count);
static void reset_filter(struct sock_fprog *fprog, struct sk_filter **filter);
static void skbtrace_filters_clean(void);

struct skbtrace_ops* skbtrace_ops_get(int af)
{
	return skbtrace_ops[af];
}
EXPORT_SYMBOL_GPL(skbtrace_ops_get);

static void skbtrace_proto_load(void)
{
	int af;

	if (!should_load_proto)
		return;

	should_load_proto = false;

	for (af = AF_UNSPEC; af < AF_MAX; af++) {
		/* load proto-specific events */
		if (!af_tp_list[af])
			request_module("skbtrace-af-%d", af);
	}
}

void __skbtrace_block_probe(struct skbtrace_block *blk)
{
	unsigned int chan_id;
	struct rchan *rchan;

	chan_id = (!!in_irq()) << 1;
	chan_id |= !!in_softirq();	/* make sparse happy */
	rchan = skbtrace_channels[chan_id];

	if (unlikely(chan_id >= HW))
		relay_write(rchan, blk, blk->len);
	else {
		local_bh_disable();
		__relay_write(rchan, blk, blk->len);
		local_bh_enable();
	}
	blk->action = skbtrace_action_invalid;
}

void __skbtrace_do_probe(struct skbtrace_tracepoint *tp,
				struct skbtrace_context *ctx,
				struct skbtrace_block *blk)
{
	int i;
	char *sec_blk;
	struct secondary_buffer *buf;

	if (ctx)
		buf = secondary_table_lookup(&ctx->sec_table, tp);
	else
		buf = &tp->sec_buffer;

	if (!buf) {
		if (tp->nr_secondary)
			blk->flags |= 1<<skbtrace_flags_miss_secondary;
		goto quit;
	}

	spin_lock_bh(&buf->lock);
	for (i = 0; i < buf->count; i++) {
		if (--buf->offset < 0)
			buf->offset = SECONDARY_BUFFER_COUNTS - 1;
		sec_blk = &buf->slots[buf->offset * SECONDARY_BUFFER_UNIT];
		__skbtrace_block_probe((struct skbtrace_block*)sec_blk);
	}
	secondary_buffer_reset(buf);
	spin_unlock_bh(&buf->lock);

quit:
	__skbtrace_block_probe(blk);
}

void __skbtrace_probe(struct skbtrace_tracepoint *tp,
				struct skbtrace_context *ctx,
				struct skbtrace_block *blk)
{
	if (!tp)
		return;
	if (!tp->primary)
		__skbtrace_do_probe(tp, ctx, blk);
}
EXPORT_SYMBOL_GPL(__skbtrace_probe);

static void __skbtrace_setup_tracepoints(struct skbtrace_tracepoint *tp_list)
{
	struct skbtrace_tracepoint *tp;

	tp = tp_list;
	while (tp && tp->trace_name) {
		secondary_buffer_init(&tp->sec_buffer, tp);
		tp->primary = NULL;
		tp->enabled = 0;
		tp++;
	}
}

static int __skbtrace_register_tracepoints(int af,
                                struct skbtrace_tracepoint *tp_list)
{
	int ret = 0;

	if (af_tp_list[af])
		ret = -EEXIST;

	if (tp_list) {
		__skbtrace_setup_tracepoints(tp_list);
		if (tp_list[0].trace_name)
			af_tp_list[af] = tp_list;
		else
			ret = -EINVAL;
	} else
		af_tp_list[af] = NULL;

	return ret;
}

static void __skbtrace_unregister_tracepoints(int af)
{
	struct skbtrace_tracepoint *tp;

	tp = af_tp_list[af];
	while (tp && tp->trace_name) {
		if (tp->enabled) {
			tp->enabled = 0;
			--nr_skbtrace_enabled_tp;
			tracepoint_probe_unregister(tp->trace_name,
							tp->probe);
			secondary_buffer_put(&tp->sec_buffer);
		}
		tp++;
	}
	af_tp_list[af] = NULL;
}

static inline int __skbtrace_register_ops(int af, struct skbtrace_ops *ops)
{
	if (skbtrace_ops[af])
		return -EEXIST;
	skbtrace_ops[af] = ops;
	return 0;
}

static inline void __skbtrace_unregister_ops(int af)
{
	skbtrace_ops[af] = NULL;
}

int skbtrace_register_proto(int af,
			struct skbtrace_tracepoint *tp_list,
			struct skbtrace_ops *ops)
{
	int ret;

	if (af < 0 || af >= AF_MAX)
		return -EINVAL;

	mutex_lock(&skbtrace_lock);
	ret = __skbtrace_register_tracepoints(af, tp_list);
	if (!ret) {
		ret = __skbtrace_register_ops(af, ops);
		if (ret)
			__skbtrace_unregister_tracepoints(af);
	}
	mutex_unlock(&skbtrace_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(skbtrace_register_proto);

void skbtrace_unregister_proto(int af)
{
	if (af < 0 || af >= AF_MAX)
		return;

	mutex_lock(&skbtrace_lock);
	__skbtrace_unregister_tracepoints(af);
	__skbtrace_unregister_ops(af);
	mutex_unlock(&skbtrace_lock);

	flush_channels();
	should_load_proto = true;
}
EXPORT_SYMBOL_GPL(skbtrace_unregister_proto);

void skbtrace_context_setup(struct skbtrace_context *ctx,
				struct skbtrace_ops *ops)
{
	ctx->ops = ops;
	ctx->session = skbtrace_session;
	secondary_table_init(&ctx->sec_table);
}
EXPORT_SYMBOL(skbtrace_context_setup);

struct skbtrace_context *skbtrace_context_get(struct sock *sk)
{
	struct skbtrace_ops *ops;
	struct skbtrace_context *ctx;

	ops = skbtrace_ops_get(sk->sk_family);
	if (!ops)
		return NULL;
	local_bh_disable();

	if (sk->sk_skbtrace &&
			(skbtrace_session != sk->sk_skbtrace->session))
		skbtrace_context_destroy(&sk->sk_skbtrace);

	if (!sk->sk_skbtrace) {
		ctx = kzalloc(sizeof(struct skbtrace_context), GFP_ATOMIC);
		if (likely(ctx)) {
			skbtrace_context_setup(ctx, ops);
			sk->sk_skbtrace = ctx;
		}
	}

	local_bh_enable();
	return sk->sk_skbtrace;
}
EXPORT_SYMBOL(skbtrace_context_get);

static int subbuf_start_handler(struct rchan_buf *buf,
				void *subbuf,
				void *prev_subbuf,
				size_t prev_padding)
{
	if (relay_buf_full(buf)) {
		long trace, cpu;

		trace = (long)buf->chan->private_data;
		cpu = buf->cpu;
		skbtrace_dropped[trace][cpu]++;
		return 0;
	}
	return 1;
}

static struct dentry *create_buf_file_handler(const char *filename,
					      struct dentry *parent,
					      int mode,
					      struct rchan_buf *buf,
					      int *is_global)
{
	return debugfs_create_file(filename, mode, parent, buf,
				       &relay_file_operations);
}

static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static struct rchan_callbacks relayfs_callbacks = {
	.subbuf_start = subbuf_start_handler,
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
};

/* caller must hold skbtrace_lock */
static int create_channels(void)
{
	unsigned long i, created;
	const char *skbtrace_names[NR_CHANNELS] = {    "trace.syscall.cpu",
							"trace.softirq.cpu",
							"trace.hardirq.cpu" };
	created = 0;
	for (i = 0; i < NR_CHANNELS; i++) {
		if (skbtrace_channels[i])
			continue;
		skbtrace_channels[i] = relay_open(skbtrace_names[i],
			skbtrace_dentry, subbuf_size, subbuf_nr,
				&relayfs_callbacks, (void *)i);
		if (!skbtrace_channels[i]) {
			destroy_channels();
			return -ENOMEM;
		}
		created = 1;
	}
	skbtrace_channels[HW + 1] = skbtrace_channels[HW];

	if (created)
		__module_get(THIS_MODULE);
	return 0;
}

static void flush_channels(void)
{
	int i;
	for (i = 0; i < NR_CHANNELS; i++) {
		if (skbtrace_channels[i])
			relay_flush(skbtrace_channels[i]);
	}
}

/* caller must hold skbtrace_lock */
static void destroy_channels(void)
{
	int i, removed;

	removed = 0;
	for (i = 0; i < NR_CHANNELS; i++) {
		if (skbtrace_channels[i]) {
			relay_flush(skbtrace_channels[i]);
			relay_close(skbtrace_channels[i]);
			skbtrace_channels[i] = NULL;
			removed = 1;
		}
	}
	skbtrace_channels[HW + 1] = NULL;

	if (removed)
		module_put(THIS_MODULE);
}

static void remove_controls(void)
{
#define REMOVE_DEBUGFS_FILE(name) \
	do {\
		if (name##_control) \
			debugfs_remove(name##_control); \
	} while(0);

	REMOVE_DEBUGFS_FILE(enabled)
	REMOVE_DEBUGFS_FILE(dropped)
	REMOVE_DEBUGFS_FILE(version)
	REMOVE_DEBUGFS_FILE(subbuf_nr)
	REMOVE_DEBUGFS_FILE(subbuf_size)
	REMOVE_DEBUGFS_FILE(filters)
	REMOVE_DEBUGFS_FILE(sock_filters)
}

static int create_controls(void)
{
#define CREATE_DEBUGFS_FILE(name)\
	do {\
		name##_control = debugfs_create_file(#name, 0,\
				skbtrace_dentry, NULL, &name##_fops);\
		if (name##_control)\
			break;\
		pr_err("skbtrace: couldn't create relayfs file '" #name "'\n");\
		goto fail;\
	} while (0);

	CREATE_DEBUGFS_FILE(enabled)
	CREATE_DEBUGFS_FILE(dropped)
	CREATE_DEBUGFS_FILE(version)
	CREATE_DEBUGFS_FILE(subbuf_nr)
	CREATE_DEBUGFS_FILE(subbuf_size)
	CREATE_DEBUGFS_FILE(filters)
	CREATE_DEBUGFS_FILE(sock_filters)

#undef CREATE_DEBUGFS_FILE
	return 0;
fail:
	remove_controls();
	return -1;
}

static char *skbtrace_tracepoint_default_desc(struct skbtrace_tracepoint *t)
{
	char *desc;
	int n;

	n = strlen(t->trace_name) + 64;
	desc = kmalloc(n, GFP_KERNEL);
	if (!desc)
		return NULL;

	snprintf(desc, n, "%s enabled:%d\n", t->trace_name, !!t->enabled);
	return desc;
}

static char *skbtrace_tracepoint_desc(struct skbtrace_tracepoint *tp)
{
	if (tp->desc)
		return tp->desc(tp);
	return skbtrace_tracepoint_default_desc(tp);
}

static ssize_t enabled_read(struct file *filp, char __user *buffer,
			    size_t count, loff_t *ppos)
{
	size_t ret, offset, len;
	struct skbtrace_tracepoint *tp;
	int af;
	char *desc = NULL;

	skbtrace_proto_load();

	ret = offset = 0;
	mutex_lock(&skbtrace_lock);
	for (af = AF_UNSPEC; af < AF_MAX; af++) {
		tp = af_tp_list[af];
		while (tp && tp->trace_name) {
			kfree(desc);
			desc = skbtrace_tracepoint_desc(tp);
			if (!desc)
				return -ENOMEM;
			len = strlen(desc);
			offset += len;
			if (offset <= *ppos) {
				++tp;
				continue;
			}
			if (count < len) {
				ret = -EINVAL;
				goto unlock;
			}
			if (copy_to_user(buffer, desc, len)) {
				ret = -EFAULT;
				goto unlock;
			}
			*ppos += len;
			ret = len;
			goto unlock;
		}
	}
unlock:
	kfree(desc);
	mutex_unlock(&skbtrace_lock);

	return ret;
}

static struct skbtrace_tracepoint *skbtrace_lookup_tp(char *name)
{
	int af;
	struct skbtrace_tracepoint *tp;

	for (af = AF_UNSPEC; af < AF_MAX; af++) {
		tp = af_tp_list[af];
		while (tp && tp->trace_name) {
			if (!strcmp(name, tp->trace_name))
				return tp;
			++tp;
		}
	}

	return NULL;
}

struct skbtrace_options_context {
	char *name;
	char *options;
	struct skbtrace_tracepoint *primary;
};

struct option_handler {
	char *key;
	int (*handler)(struct skbtrace_options_context *ctx, char *val);
};

static int handle_primary_option(struct skbtrace_options_context *ctx, char *val)
{
	ctx->primary = skbtrace_lookup_tp(val);
	if (!ctx->primary)
		return -EINVAL;
	return 0;
}

static struct option_handler common_handlers[] = {
	{
		.key = "primary=",
		.handler = handle_primary_option,
	},
	{
		.key = NULL,
	},
};

static int handle_options(char *event_spec, struct option_handler *handlers,
					struct skbtrace_options_context *ctx)
{
	char *option;

	memset(ctx, 0, sizeof(*ctx));
	ctx->options = strchr(event_spec, ',');
	if (!ctx->options)
		return 0;
	*(ctx->options) = '\x0';
	option = ++(ctx->options);

	while (option && *option) {
		char *end;
		struct option_handler *h;

		end = strchr(option, ',');
		if (end)
			*end = '\x0';
		h = &handlers[0];
		while (h->key) {
			if (strstr(option, h->key) == option) {
				int ret;
				char *val;

				val = option + strlen(h->key);
				ret = h->handler(ctx, val);
				if (!ret)
					break;
				else
					return -EINVAL;
			}
			h++;
		}
		if (!h->key) {
			if (end) {
				*end = ',';
				option = end + 1;
			} else
				break;
		} else {
			if (end) {
				memmove(option, end + 1, strlen(end + 1) + 1);
			} else
				*option = '\x0';
		}
	}

	return 0;
}

static int __enable_tp(struct skbtrace_tracepoint *tp,
				struct skbtrace_options_context *ctx)
{
	int ret = 0;

	if (tp->enabled)
		return -EBUSY;

	if (tp->enable)
		tp->enable(tp);
	ret = tracepoint_probe_register(tp->trace_name, tp->probe);
	if (!ret) {
		tp->primary = ctx->primary;
		if (tp->primary)
			tp->primary->nr_secondary++;
		tp->enabled = 1;
	} else {
		if (tp->disable)
			tp->disable(tp);
	}

	return ret;
}

static int __disable_tp(struct skbtrace_tracepoint *tp)
{
	int ret;

	if (!tp->enabled)
		return -EINVAL;

	ret = tracepoint_probe_unregister(tp->trace_name, tp->probe);
	if (ret)
		return ret;

	if (tp->disable)
		tp->disable(tp);
	if (tp->primary) {
		secondary_buffer_put(&tp->primary->sec_buffer);
		tp->primary->nr_secondary--;
	}
	tp->enabled = 0;
	return 0;
}

static int skbtrace_enable_tp(char *event_spec)
{
	struct skbtrace_options_context ctx;
	int ret;
	struct skbtrace_tracepoint *tp;

	ret = handle_options(event_spec, common_handlers, &ctx);
	if (ret)
		return ret;
	ctx.name = event_spec;

	mutex_lock(&skbtrace_lock);
	if (!nr_skbtrace_enabled_tp) {
		ret = create_channels();
		if (ret)
			goto unlock;
	}

	tp = skbtrace_lookup_tp(ctx.name);
	if (!tp || tp->enabled) {
		ret = -EINVAL;
		goto unlock;
	}

	if (ctx.options && tp->setup_options) {
		ret = tp->setup_options(tp, ctx.options);
		if (ret)
			goto unlock;
	}

	ret = __enable_tp(tp, &ctx);

	if (ret && !nr_skbtrace_enabled_tp)
		destroy_channels();
	else if (!ret)
		++nr_skbtrace_enabled_tp;

unlock:
	mutex_unlock(&skbtrace_lock);
	return ret;
}

static int skbtrace_disable_all_tp(void)
{
	int ret, af;
	struct skbtrace_tracepoint *tp;

	/*
	 * '-*' has two meanings:
	 *
	 *   (0) first time, it disables all tracepoints, and flush channels.
	 *   (1) second time, it removes all channels.
	 */

	if (!nr_skbtrace_enabled_tp) {
		skbtrace_filters_clean();
		++skbtrace_session;
		destroy_channels();
		return 0;
	}

	ret = -EINVAL;
	mutex_lock(&skbtrace_lock);
	for (af = AF_UNSPEC; af < AF_MAX; af++) {
		tp = af_tp_list[af];
		while (tp && tp->trace_name) {
			ret = __disable_tp(tp);
			if (!ret)
				--nr_skbtrace_enabled_tp;
			++tp;
		}
	}
	mutex_unlock(&skbtrace_lock);
	flush_channels();

	return ret;
}

/* The user given buffer should contains such like string:
 *	(0) To enable a skbtrace event:	"TRACE_NAME,opt1=val1,opt2=val2,..."
 *	(1) To disable all skbtrace events:"-*"
 */
static ssize_t enabled_write(struct file *filp, const char __user *buffer,
			     size_t count, loff_t *ppos)
{
	char kbuf[TRACE_SPEC_MAX_LEN+1];
	int ret;

	skbtrace_proto_load();

	if (count >= TRACE_SPEC_MAX_LEN)
		return -EINVAL;
	if (copy_from_user(kbuf, buffer, count))
		return -EFAULT;
	kbuf[count] = '\x0';

	if (strcmp("-*", kbuf))
		ret = skbtrace_enable_tp(&kbuf[0]);
	else
		ret = skbtrace_disable_all_tp();

	return ret ?: count;
}

static int kmod_open(struct inode *inodep, struct file *filp)
{
	__module_get(THIS_MODULE);
	return 0;
}

static int kmod_release(struct inode *inodep, struct file *filp)
{
	module_put(THIS_MODULE);
	return 0;
}

static const struct file_operations enabled_fops = {
	.owner =	THIS_MODULE,
	.open =		kmod_open,
	.release =	kmod_release,
	.read =		enabled_read,
	.write =	enabled_write,
};

static ssize_t dropped_read(struct file *filp, char __user *buffer,
			    size_t count, loff_t *ppos)
{

	char buf[256];
	unsigned long skbtrace_total_dropped[NR_CHANNELS] = {0, 0, 0};
	int cpu;

	for_each_possible_cpu(cpu) {
		skbtrace_total_dropped[HW] += skbtrace_dropped[HW][cpu];
		skbtrace_total_dropped[SI] += skbtrace_dropped[SI][cpu];
		skbtrace_total_dropped[SC] += skbtrace_dropped[SC][cpu];
	}

	snprintf(buf, sizeof(buf), "%lu %lu %lu\n",
		skbtrace_total_dropped[HW],
		skbtrace_total_dropped[SI],
		skbtrace_total_dropped[SC]
		);

	return simple_read_from_buffer(buffer, count, ppos,
				       buf, strlen(buf));
}

static ssize_t dropped_write(struct file *filp, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	memset(skbtrace_dropped, 0, sizeof(skbtrace_dropped));
	return count;
}

static const struct file_operations dropped_fops = {
	.owner =	THIS_MODULE,
	.open =		kmod_open,
	.release =	kmod_release,
	.read =		dropped_read,
	.write =	dropped_write,
};

static ssize_t version_read(struct file *filp, char __user *buffer,
			    size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buffer, count, ppos,
				       SKBTRACE_VERSION "\n",
					strlen(SKBTRACE_VERSION "\n"));
}

static const struct file_operations version_fops = {
	.owner =	THIS_MODULE,
	.open =		kmod_open,
	.release =	kmod_release,
	.read =		version_read,
};

static ssize_t subbuf_x_read(struct file *filp, char __user *buffer,
			    size_t count, loff_t *ppos, int which)
{
	char buf[24];

	sprintf(buf, "%d\n", which);
	return simple_read_from_buffer(buffer, count, ppos,
				       buf, strlen(buf));
}

static ssize_t subbuf_x_write(struct file *filp, const char __user *buffer,
			    size_t count, loff_t *ppos,
			    int *which, int min_val, int max_val)
{
	char buf[24];
	int v;

	if (nr_skbtrace_enabled_tp)
		return -EBUSY;

	if (!buffer || count > sizeof(buf) - 1)
		return -EINVAL;
	memset(buf, 0, sizeof(buf));
	if (copy_from_user(buf, buffer, count))
		return -EFAULT;
	if (sscanf(buf, "%d", &v) != 1)
		return -EINVAL;
	if (v < min_val || v > max_val)
		return -EINVAL;

	*which = v;
	return count;
}

static ssize_t subbuf_nr_read(struct file *filp, char __user *buffer,
			    size_t count, loff_t *ppos)
{
	return subbuf_x_read(filp, buffer, count, ppos, subbuf_nr);
}

static ssize_t subbuf_nr_write(struct file *filp, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	return subbuf_x_write(filp, buffer, count, ppos, &subbuf_nr,
			SKBTRACE_MIN_SUBBUF_NR, SKBTRACE_MAX_SUBBUF_NR);
}

static const struct file_operations subbuf_nr_fops = {
	.owner =	THIS_MODULE,
	.open =		kmod_open,
	.release =	kmod_release,
	.read =		subbuf_nr_read,
	.write =	subbuf_nr_write,
};

static ssize_t subbuf_size_read(struct file *filp, char __user *buffer,
			    size_t count, loff_t *ppos)
{
	return subbuf_x_read(filp, buffer, count, ppos, subbuf_size);
}

static ssize_t subbuf_size_write(struct file *filp, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	return subbuf_x_write(filp, buffer, count, ppos, &subbuf_size,
			SKBTRACE_MIN_SUBBUF_SIZE, SKBTRACE_MAX_SUBBUF_SIZE);
}

static const struct file_operations subbuf_size_fops = {
	.owner =	THIS_MODULE,
	.open =		kmod_open,
	.release =	kmod_release,
	.read =		subbuf_size_read,
	.write =	subbuf_size_write,
};

struct sk_buff* skbtrace_get_twsk_filter_skb(struct inet_timewait_sock *tw)
{
	unsigned int cpu;
	struct sk_buff **p_skb;
	int ret;
	struct skbtrace_ops *ops;

	local_bh_disable();

	ops = skbtrace_ops_get(tw->tw_family);
	if (!ops || !ops->filter_skb) {
		local_bh_enable();
		return NULL;
	}

	cpu = smp_processor_id();
	p_skb = per_cpu_ptr(sock_filter_skb, cpu);
	if (unlikely(!*p_skb)) {
		*p_skb = alloc_skb(1500, GFP_ATOMIC);
		if (!*p_skb) {
			local_bh_enable();
			return NULL;
		}
	}

	ret = ops->tw_filter_skb(tw, *p_skb);
	if (ret < 0) {
		skbtrace_put_twsk_filter_skb(*p_skb);
		return NULL;
	}

	return *p_skb;
}
EXPORT_SYMBOL_GPL(skbtrace_get_twsk_filter_skb);

struct sk_buff* skbtrace_get_sock_filter_skb(struct sock *sk)
{
	unsigned int cpu;
	struct sk_buff **p_skb;
	int ret;
	struct skbtrace_ops *ops;

	local_bh_disable();

	ops = skbtrace_ops_get(sk->sk_family);
	if (!ops || !ops->filter_skb) {
		local_bh_enable();
		return NULL;
	}

	cpu = smp_processor_id();
	p_skb = per_cpu_ptr(sock_filter_skb, cpu);
	if (unlikely(!*p_skb)) {
		*p_skb = alloc_skb(1500, GFP_ATOMIC);
		if (!*p_skb) {
			local_bh_enable();
			return NULL;
		}
	}

	ret = ops->filter_skb(sk, *p_skb);
	if (ret < 0) {
		skbtrace_put_sock_filter_skb(*p_skb);
		return NULL;
	}

	return *p_skb;
}
EXPORT_SYMBOL_GPL(skbtrace_get_sock_filter_skb);

static ssize_t sk_filter_read(struct sock_fprog *fprog, char __user *buffer,
							    size_t count)
{
	int sz_filter;
	struct sock_filter __user *user_filter;

	if (!fprog || !fprog->filter)
		return -EINVAL;
	sz_filter = fprog->len * sizeof(struct sock_filter);
	if (count < sizeof(struct sock_fprog) + sz_filter)
		return -EINVAL;

	if (copy_to_user(buffer, &fprog->len, sizeof(short)))
		return -EFAULT;

	if (copy_from_user(&user_filter,
			buffer + sizeof(short), sizeof(user_filter)))
		return -EFAULT;
	if (copy_to_user(user_filter, fprog->filter, sz_filter))
		return -EFAULT;

	return sizeof(struct sock_fprog) + sz_filter;
}

static ssize_t sk_filter_write(struct sock_fprog *sk_fprog,
				struct sk_filter **sk_filter,
				const char __user *buffer, size_t count)
{
	int sz_filter, ret;
	struct sock_filter __user *user_filter;

	if (count < sizeof(struct sock_fprog) || sk_fprog->filter)
		return -EINVAL;
	if (copy_from_user(sk_fprog, buffer, sizeof(struct sock_fprog)))
		return -EFAULT;
	sz_filter = sk_fprog->len * sizeof(struct sock_filter);
	user_filter = sk_fprog->filter;

	sk_fprog->filter = kzalloc(sz_filter, GFP_KERNEL);
	if (!sk_fprog->filter)
		ret = -ENOMEM;

	ret = -EFAULT;
	if (!copy_from_user(sk_fprog->filter, user_filter, sz_filter)) {
		ret = sk_unattached_filter_create(sk_filter, sk_fprog);
		if (ret) {
			reset_filter(sk_fprog, sk_filter);
			return ret;
		}
	}
	jump_label_inc(&skbtrace_filters_enabled);
	return sizeof(struct sock_fprog) + sz_filter;
}

static ssize_t filters_read(struct file *filp, char __user *buffer,
			size_t count, loff_t *ppos, struct sock_fprog *fprog)
{
	return sk_filter_read(fprog, buffer, count);
}

static ssize_t skb_filters_read(struct file *filp, char __user *buffer,
						size_t count, loff_t *ppos)
{
	return filters_read(filp, buffer, count, ppos, &skb_filter_fprog);
}

static ssize_t sock_filters_read(struct file *filp, char __user *buffer,
						size_t count, loff_t *ppos)
{
	return filters_read(filp, buffer, count, ppos, &sock_filter_fprog);
}

static ssize_t filters_write(struct file *filp, const char __user *buffer,
						size_t count, loff_t *ppos,
			struct sock_fprog *fprog, struct sk_filter **filter)

{
	skbtrace_proto_load();

	if (nr_skbtrace_enabled_tp)
		return -EBUSY;
	reset_filter(fprog, filter);
	return sk_filter_write(fprog, filter, buffer, count);
}

static ssize_t skb_filters_write(struct file *filp, const char __user *buffer,
						size_t count, loff_t *ppos)
{
	return filters_write(filp, buffer, count, ppos,
			&skb_filter_fprog, &skbtrace_skb_filter);
}

static ssize_t sock_filters_write(struct file *filp, const char __user *buffer,
						size_t count, loff_t *ppos)
{
	if (unlikely(!++skbtrace_sock_filter_id))
		skbtrace_sock_filter_id = 1;
	return filters_write(filp, buffer, count, ppos,
				&sock_filter_fprog, &skbtrace_sock_filter);
}

static const struct file_operations filters_fops = {
	.owner =	THIS_MODULE,
	.open =		kmod_open,
	.release =	kmod_release,
	.read =		skb_filters_read,
	.write =	skb_filters_write,
};

static const struct file_operations sock_filters_fops = {
	.owner =	THIS_MODULE,
	.open =		kmod_open,
	.release =	kmod_release,
	.read =		sock_filters_read,
	.write =	sock_filters_write,
};

static void reset_filter(struct sock_fprog *fprog, struct sk_filter **filter)
{
	if (fprog->filter)
		kfree(fprog->filter);
	memset(fprog, 0, sizeof(struct sock_fprog));

	if (*filter) {
		jump_label_dec(&skbtrace_filters_enabled);
		sk_unattached_filter_destroy(*filter);
		*filter = NULL;
	}
}

static void skbtrace_filters_clean(void)
{
	reset_filter(&sock_filter_fprog, &skbtrace_sock_filter);
	reset_filter(&skb_filter_fprog, &skbtrace_skb_filter);
}

static void clean_skbtrace_filters(void)
{
	unsigned int cpu;

	if (skb_filter_fprog.filter)
		kfree(skb_filter_fprog.filter);
	if (skbtrace_skb_filter) {
		jump_label_dec(&skbtrace_filters_enabled);
		sk_unattached_filter_destroy(skbtrace_skb_filter);
	}

	if (sock_filter_fprog.filter)
		kfree(sock_filter_fprog.filter);
	if (skbtrace_sock_filter) {
		jump_label_dec(&skbtrace_filters_enabled);
		sk_unattached_filter_destroy(skbtrace_sock_filter);
	}

	for_each_possible_cpu(cpu) {
		struct sk_buff **p_skb;

		p_skb = per_cpu_ptr(sock_filter_skb, cpu);
		if (*p_skb)
			kfree_skb(*p_skb);
	}
	free_percpu(sock_filter_skb);
}

static int setup_skbtrace_filters(void)
{
	unsigned int cpu, err;

	skbtrace_sock_filter_id = random32();

	skbtrace_filters_clean();

	sock_filter_skb = alloc_percpu(struct sk_buff*);
	err = 0;
	for_each_possible_cpu(cpu) {
		struct sk_buff **p_skb;

		p_skb = per_cpu_ptr(sock_filter_skb, cpu);
		if (cpu_online(cpu)) {
			*p_skb = alloc_skb(1500, GFP_KERNEL);
			if (!*p_skb)
				err = 1;
		} else
			*p_skb = NULL;
	}

	if (err) {
		clean_skbtrace_filters();
		return -ENOMEM;
	}
	return 0;
}

static int skbtrace_init(void)
{
	mutex_init(&skbtrace_lock);
	if (!skbtrace_session)
		skbtrace_session = random32();

	if (setup_skbtrace_filters() < 0)
		return -ENOMEM;

	if (skbtrace_events_common_init())
		return -ENODEV;

	skbtrace_dentry = debugfs_create_dir(SKBTRACE_DIR, NULL);
	if (!skbtrace_dentry)
		return -ENOMEM;

	if (create_controls()) {
		debugfs_remove(skbtrace_dentry);
		return -ENOMEM;
	}

	should_load_proto = true;
	return 0;
}

static void skbtrace_exit(void)
{
	skbtrace_disable_all_tp(); /* disable all enabled tracepoints */
	skbtrace_disable_all_tp(); /* remove channels in debugfs at 2nd time */
	if (unlikely(nr_skbtrace_enabled_tp))
		pr_err("skbtrace: failed to clean tracepoints.\n");
	remove_controls();
	debugfs_remove(skbtrace_dentry);
	clean_skbtrace_filters();
}

module_init(skbtrace_init);
module_exit(skbtrace_exit);
MODULE_LICENSE("GPL");
