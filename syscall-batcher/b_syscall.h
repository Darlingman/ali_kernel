#ifndef B_SYSCALL_H_
#define N_SYSCALL_H_

#ifndef B_SYSCALL
#define B_SYSCALL	0
#endif

#if B_SYSCALL == 0

struct syscall_batcher;

static inline int syscall_batcher_create(struct syscall_batcher **batcher,
			void *data,
                        void (*post_batch)(struct syscall_batcher*, void*))
{
	return 0;
}

static inline void syscall_batcher_reset(struct syscall_batcher *b)
{
}

static inline int syscall_batcher_add(struct syscall_batcher *b,
				long op, unsigned long args[MAX_NR_SYSCALL_PARAMETERS])
{
	return 0;
}

static inline int syscall_batcher_flush(struct syscall_batcher *b)
{
	return 0;
}

static inline void syscall_batcher_free(struct syscall_batcher *b)
{
}

#else

#define _GNU_SOURCE        /* or _BSD_SOURCE or _SVID_SOURCE */
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <stdlib.h>	   /* For free() */

#define MAX_BATCH_SYSCALL	32

#define MAX_NR_SYSCALL_PARAMETERS	6

struct syscall_entry {
	long op;
	long ret;
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS];
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
 
struct syscall_batcher {
	/* below two fields have to place together */
	struct syscall_page_header scp;
	struct syscall_entry entries[MAX_BATCH_SYSCALL];
	int fd;
	int flushed;
	void (*post_batch)(struct syscall_batcher*, void*);
	void *post_batch_data;
	void *context[MAX_BATCH_SYSCALL];
};

extern int  syscall_batcher_create(struct syscall_batcher **batcher,
			void *data,
			void (*post_batch)(struct syscall_batcher *, void *));
extern void syscall_batcher_reset(struct syscall_batcher *b);

extern int syscall_batcher_add(struct syscall_batcher *b,
			long op, unsigned long args[MAX_NR_SYSCALL_PARAMETERS],
			void *context);
extern int syscall_batcher_flush(struct syscall_batcher *b);

static inline void syscall_batcher_free(struct syscall_batcher *b)
{
	if (b)
		free(b);
}

static inline ssize_t b_sendto(struct syscall_batcher *b, void *context,
			int sockfd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, socklen_t addrlen)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)sockfd,
		(unsigned long)buf,
		(unsigned long)len,
		(unsigned long)flags,
		(unsigned long)dest_addr,
		(unsigned long)addrlen,
	};

	return syscall_batcher_add(b, SYS_sendto, args, context);
}

static inline ssize_t b_recvfrom(struct syscall_batcher *b, void *context,
			int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)sockfd,
		(unsigned long)buf,
		(unsigned long)len,
		(unsigned long)flags,
		(unsigned long)src_addr,
		(unsigned long)addrlen,
	};

	return syscall_batcher_add(b, SYS_recvfrom, args, context);
}

static inline ssize_t b_sendmsg(struct syscall_batcher *b, void *context,
		int sockfd, const struct msghdr *msg, int flags)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)sockfd,
		(unsigned long)msg,
		(unsigned long)flags,
	};

	return syscall_batcher_add(b, SYS_sendmsg, args, context);
}

static inline ssize_t b_recvmsg(struct syscall_batcher *b, void *context,
		int sockfd, struct msghdr *msg, int flags)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)sockfd,
		(unsigned long)msg,
		(unsigned long)flags,
	};

	return syscall_batcher_add(b, SYS_recvmsg, args, context);
}

static inline int b_accept(struct syscall_batcher *b, void *context,
		int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)sockfd,
		(unsigned long)addr,
		(unsigned long)addrlen
	};

	return syscall_batcher_add(b, SYS_accept, args, context);
}

static inline int b_read(struct syscall_batcher *b, void *context,
	int fd, void *buf, size_t count)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)fd,
		(unsigned long)buf,
		(unsigned long)count,
	};

	return syscall_batcher_add(b, SYS_read, args, context);
}

static inline int b_pread64(struct syscall_batcher *b, void *context,
	int fd, void *buf, size_t count, off_t offset)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)fd,
		(unsigned long)buf,
		(unsigned long)count,
		(unsigned long)offset,
	};

	return syscall_batcher_add(b, SYS_pread64, args, context);
}

static inline int b_pwrite64(struct syscall_batcher *b, void *context,
	int fd, const void *buf, size_t count, off_t offset)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)fd,
		(unsigned long)buf,
		(unsigned long)count,
		(unsigned long)offset,
	};

	return syscall_batcher_add(b, SYS_pwrite64, args, context);
}

static inline int b_write(struct syscall_batcher *b, void *context,
	int fd, void *buf, size_t count)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)fd,
		(unsigned long)buf,
		(unsigned long)count,
	};

	return syscall_batcher_add(b, SYS_write, args, context);
}

static inline int b_close(struct syscall_batcher *b, void *context,
		int fd)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)fd,
	};

	return syscall_batcher_add(b, SYS_close, args, context);
}

static inline int b_epoll_create(struct syscall_batcher *b, void *context,
		int size)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)size,
	};

	return syscall_batcher_add(b, SYS_epoll_create, args, context);
}

static inline int b_epoll_ctl(struct syscall_batcher *b, void *context,
			int epfd, int op, int fd, struct epoll_event *event)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)epfd,
		(unsigned long)op,
		(unsigned long)fd,
		(unsigned long)event,
	};

	return syscall_batcher_add(b, SYS_epoll_ctl, args, context);
}


static inline pid_t b_getpid(struct syscall_batcher *b, void *context)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
	};
	return syscall_batcher_add(b, SYS_getpid, args, context);
}

#define SYS_batch_epoll_ctl	-1
#define SYS_batch_accept4	-2

struct batch_epoll_ctl_arg {
	int op;
	int fd;
	struct epoll_event event;
	void *context;
};

static inline int b_batch_epoll_ctl(struct syscall_batcher *b, void *context,
			int fd, struct batch_epoll_ctl_arg *epc_args,
						int *total)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)fd,
		(unsigned long)epc_args,
		(unsigned long)total,
	};
	return syscall_batcher_add(b, SYS_batch_epoll_ctl, args, context);
}

struct batch_accept4_arg {
	int fd;
	int peer_addrlen;
	struct sockaddr peer;
};

static inline int b_batch_accept4(struct syscall_batcher *b, void *context,
			int fd, struct batch_accept4_arg *a_args,
					int *total, int flags)
{
	unsigned long args[MAX_NR_SYSCALL_PARAMETERS] = {
		(unsigned long)fd,
		(unsigned long)a_args,
		(unsigned long)total,
		(unsigned long)flags,
	};
	return syscall_batcher_add(b, SYS_batch_accept4, args, context);
}

static inline unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32);
}

#define NR 1000

#endif /* #if B_SYSCALL != 0 */

#endif /* B_SYSCALL_H_ */
