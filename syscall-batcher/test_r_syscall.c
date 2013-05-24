#include "b_syscall.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

void pressure(void)
{
	int i, j;
	int epfd[MAX_BATCH_SYSCALL];
	long n;
	unsigned long long start, end;

	start = rdtsc();
	n = 0;
	for (i = 0; i < NR * MAX_BATCH_SYSCALL; i++) {
		for (j = 0; j < MAX_BATCH_SYSCALL; j++) {
			epfd[j] = epoll_create(1024);
//			epfd[j] = getpid();
			if (epfd[j] < 0) {
				printf("%d/%d epoll_create() error %d/%m\n",
						i, j, errno);
				goto quit;
			}
		}
		n += MAX_BATCH_SYSCALL;
		for (j = 0; j < MAX_BATCH_SYSCALL; j++)
			close(epfd[j]);
//			getpid();
		n += MAX_BATCH_SYSCALL;
	}
quit:
	end = rdtsc();
	printf("%ld syscalls, %lld cycles\n", n, end - start);
}

int main(int argc, char *argv[])
{
	pressure();
	return 0;
}
