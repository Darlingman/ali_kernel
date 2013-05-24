#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b_syscall.h"

#define MAGIC 0xAFCCB99C
#define VERSION	0x1

#ifndef DEBUG
#define DEBUG 0
#endif

static struct syscall_batcher* syscall_batcher_alloc(int total)
{
	struct syscall_batcher *b;
	size_t bytes;

	bytes = sizeof(struct syscall_batcher);
	b = malloc(bytes);
	if (b)
		memset(b, 0, bytes);
	return b;
}

static inline int vaildate_syscall_page(struct syscall_batcher *b)
{
	return (b->scp.magic != MAGIC || b->scp.version != VERSION);
}

int syscall_batcher_create(struct syscall_batcher **batcher,
				void *data,
				void (*post_batch)(struct syscall_batcher*, void*))
{
	int ret;
	struct syscall_batcher *b;
	size_t bytes;

	b = syscall_batcher_alloc(MAX_BATCH_SYSCALL);
	if (!b) {
		ret = -ENOMEM;
		goto quit;
	}
	b->fd = open("/dev/syscall-batcher", O_RDWR);
	if (b->fd < 0) {
		ret = -errno;
		goto quit;
	}
	bytes = read(b->fd, &b->scp, sizeof(b->scp));
	if (bytes < sizeof(b->scp) || vaildate_syscall_page(b)) {
		ret = -EINVAL;
		goto quit;
	}
	b->post_batch_data = data;
	b->post_batch = post_batch;
	*batcher = b;
	return 0;
quit:
	*batcher = NULL;
	syscall_batcher_free(b);
	return ret;
}

int syscall_batcher_flush(struct syscall_batcher *b)
{
	size_t bytes, ret;

	if (!b->scp.nr_syscalls || b->flushed) {
#if DEBUG > 1
		fprintf(stderr, "flush flushed=%d nr_syscalls=%ld\n",
			b->flushed, b->scp.nr_syscalls);
#endif
		return 0;
	}

	bytes = sizeof(struct syscall_page_header);
	bytes += b->scp.nr_syscalls * sizeof(struct syscall_entry);

#if DEBUG > 1
{
	int i;

	for (i = 0; i < b->scp.nr_syscalls; i++)
		fprintf(stderr, "ctx=%p syscall-enter/%ld(%lx, %lx, %lx, %lx, %lx, %lx) = %ld,%lx,%s\n",
				b->context[i],
				b->scp.entries[i].op,
				b->scp.entries[i].args[0],
				b->scp.entries[i].args[1],
				b->scp.entries[i].args[2],
				b->scp.entries[i].args[3],
				b->scp.entries[i].args[4],
				b->scp.entries[i].args[5],
				b->scp.entries[i].ret,
				b->scp.entries[i].ret,
				strerror(-b->scp.entries[i].ret));
}
#endif

	errno = 0;
	ret = write(b->fd, &b->scp, bytes);

#if DEBUG > 1
{
	int i;

	if (ret != bytes)
		fprintf(stderr, "write(%ld) = %ld %s\n", bytes, ret, strerror(errno));
	for (i = 0; i < b->scp.nr_syscalls; i++)
		fprintf(stderr, "ctx=%p syscall-return/%ld(%lx, %lx, %lx, %lx, %lx, %lx) = %ld,%lx,%s\n",
				b->context[i],
				b->scp.entries[i].op,
				b->scp.entries[i].args[0],
				b->scp.entries[i].args[1],
				b->scp.entries[i].args[2],
				b->scp.entries[i].args[3],
				b->scp.entries[i].args[4],
				b->scp.entries[i].args[5],
				b->scp.entries[i].ret,
				b->scp.entries[i].ret,
				strerror(-b->scp.entries[i].ret));
}
#endif

	if (ret != bytes)
		return -errno;

	b->flushed = 1;

	if (b->post_batch)
		b->post_batch(b, b->post_batch_data);

	return b->scp.nr_completed;
}

void syscall_batcher_reset(struct syscall_batcher *b)
{
	b->flushed = 0;
	b->scp.nr_syscalls = 0;
	b->scp.flags = 0;
	memset(b->scp.reserved, 0, sizeof(b->scp.reserved));
}

int syscall_batcher_add(struct syscall_batcher *b,
			long op, unsigned long args[6],
			void *context)

{
	struct syscall_entry *e;

	if (b->scp.nr_syscalls >= MAX_BATCH_SYSCALL)
		return -EBUSY;

#if DEBUG > 1
	fprintf(stderr, "syscall_batcher_add b=%p nr=%ld op=%ld context=%p\n",
				b, b->scp.nr_syscalls, op, context);
#endif

	b->flushed = 0;
	b->context[b->scp.nr_syscalls] = context;
	e = &b->scp.entries[b->scp.nr_syscalls];
	e->op = op;
	e->ret = 0;
	memcpy(e->args, args, sizeof(unsigned long)*6);

	b->scp.nr_syscalls++;

	if (b->scp.nr_syscalls >= MAX_BATCH_SYSCALL)
		return syscall_batcher_flush(b);
	return 0;
}
