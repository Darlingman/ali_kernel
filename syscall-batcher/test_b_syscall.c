#include "b_syscall.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

void write_read(struct syscall_batcher *b)
{
	int fd;
	char buf[100];

	fd = open("/tmp/ABC.txt", O_RDWR|O_CREAT|O_LARGEFILE, 0);
	if (fd < 0) {
		printf("open(): %m\n");
		exit(0);
	}

	b_write(b, NULL, fd, "A", 1);
	b_write(b, NULL, fd, "B", 1);
	b_write(b, NULL, fd, "C", 1);
	b_write(b, NULL, fd, "D", 1);
	b_write(b, NULL, fd, "\n", 1);

	b_write(b, NULL, fd, "E", 1);
	b_write(b, NULL, fd, "F", 1);
	b_write(b, NULL, fd, "G", 1);
	b_write(b, NULL, fd, "H", 1);
	b_write(b, NULL, fd, "\n", 1);

	b_write(b, NULL, fd, "X", 1);
	b_write(b, NULL, fd, "Y", 1);
	b_write(b, NULL, fd, "Z", 1);
	b_write(b, NULL, fd, ".", 1);
	b_write(b, NULL, fd, "\n", 1);

	b_pwrite64(b, NULL, fd, "EOF", 5, 15);
	b_pread64(b, NULL, fd, buf, 100, 1);
	b_close(b, NULL, fd);
	syscall_batcher_flush(b);

	puts(buf);
}

void pressure(struct syscall_batcher *b)
{
	int i, j;
	long n;
	unsigned long long start, end;

	start = rdtsc();
	n = 0;
	for (i = 0; i < NR * MAX_BATCH_SYSCALL; i++) {
		syscall_batcher_reset(b);
		for (j = 0; j < MAX_BATCH_SYSCALL; j++)
			b_epoll_create(b, NULL, 1024);
		syscall_batcher_flush(b);
		n += b->scp.nr_completed;

		syscall_batcher_reset(b);
		for (j = 0; j < MAX_BATCH_SYSCALL; j++) {
			if (b->scp.entries[j].ret < 0) {
				printf("%d/%d b_epoll_create() error %ld/%s\n",
						i, j,
						b->scp.entries[j].ret,
						strerror(-b->scp.entries[j].ret));
				goto quit;
			}
			b_close(b, NULL, b->scp.entries[j].ret);
		}
		syscall_batcher_flush(b);
		n += b->scp.nr_completed;

	}
quit:
	end = rdtsc();
	printf("%ld syscalls / %lld cycles\n", n, end - start);
}

int main(int argc, char *argv[])
{
	struct syscall_batcher *b;
	int ret;

	ret = syscall_batcher_create(&b, NULL, NULL);
	if (ret < 0) {
		printf("load syscall-batcher failed: %s\n", strerror(-ret));
		exit(0);
	}
//	write_read(b);
	pressure(b);
	syscall_batcher_free(b);

	return 0;
}
