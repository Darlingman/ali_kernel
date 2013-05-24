/**
 * Simple server.
 *
 * Measures number of new client connections per second.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Header Include Declarations */
/* Core Headers */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
/* For socket(2), bind(2), listen(2), and accept(2) */
#include <sys/socket.h>
/* For close(2) */
#include <unistd.h>
/* For IPv4 */
#include <netinet/in.h>
#include <netinet/ip.h>
/* For inet_aton(3) */
#include <arpa/inet.h>
/* For memset(3) */
#include <string.h>
/* For sigaction(2) */
#include <signal.h>
/* For setitimer(2) */
#include <sys/time.h>
/* For pthreads */
#include <pthread.h>
/* For epoll */
#include <sys/epoll.h>

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
/* used in bind_cpu() */
#include <sched.h>

#include "b_syscall.h"

#define SERVER_IP	"0.0.0.0"
#define SERVER_PORT	8080


int init_server(struct in_addr ip, uint16_t port, int cpu);
int init_zero_server(int port);

void exit_cleanup(void)
{
	exit(EXIT_FAILURE);
}

int init_zero_server(int port)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int serverfd;
	int on = 1;

	if ((serverfd =
	     socket(AF_INET, SOCK_STREAM | O_NONBLOCK, 0)) == -1) {
		perror("Unable to open socket");
		exit(0);
	}

	setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* Configure address parameters for binding */
	memset(&addr, 0, addrlen);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	/* Bind the socket */
	if (bind(serverfd, (struct sockaddr *) &addr, addrlen) == -1) {
		perror("Unable to bind socket");
		exit(0);
	}
	
	return serverfd;
}

void test_epoll_ctl(struct syscall_batcher *b)
{
#define TOTAL	10
	struct batch_epoll_ctl_arg args[10];
	int i, epfd;

	epfd = epoll_create(1024);
	if (epfd < 0) {
		printf("epoll_create(): %m\n");
		return;
	}

	for (i = 0; i < TOTAL; i++) {
		args[i].fd = init_zero_server(29090+i);
		args[i].op = EPOLL_CTL_ADD;
		args[i].event.events = EPOLLIN;
		args[i].context = NULL;
	}
	syscall_batcher_reset(b);
	b_batch_epoll_ctl(b, NULL, epfd, args, &i);
	syscall_batcher_flush(b);

	for (i = 0; i < TOTAL; i++)
		close(args[i].fd);
	close(epfd);

	if (b->scp.entries[0].ret < 0)
		printf("batch_epoll_ctl(): %s\n", strerror(-b->scp.entries[0].ret));

	return;
#undef TOTAL
}

void test_accept4(struct syscall_batcher *b,
			struct in_addr listenip, int param_port)
{
	int serverfd;
	struct batch_accept4_arg args[10];
	int total;
	long sum;

	serverfd = init_server(listenip, param_port, -1);
	sum = 0;
	while (1) {
		long ret;

		syscall_batcher_reset(b);
		total = 10;
		b_batch_accept4(b, NULL, serverfd, &args[0], &total, 0);
		syscall_batcher_flush(b);
		ret = b->scp.entries[0].ret;
		if (!ret || EAGAIN == -ret) {
			if (total <= 0)
				continue;
			sum+=total;
			printf("%d ", total);
			syscall_batcher_reset(b);
			while (--total >=0) {
#if 0
				struct sockaddr_in *in;

				in = (struct sockaddr_in*)&args[total].peer;
				printf("peer=%s:%d\n",
					inet_ntoa(in->sin_addr),
					ntohs(in->sin_port));
#endif
				b_close(b, NULL, args[total].fd);
			}
			syscall_batcher_flush(b);
		} else {
			printf("%ld. %s\n", sum, strerror(-ret));
			exit(ret);
		}
	}
}

int main(int argc, char *argv[])
{
	struct syscall_batcher *b;
	int param_port = SERVER_PORT;
	char *param_listenip = SERVER_IP;
	struct in_addr listenip;
	int ret;

	if (argc >= 3) {
		param_listenip = argv[1];
		sscanf(argv[2], "%d", &param_port);
	}

	if (inet_aton(param_listenip, &listenip) == 0) {
		fprintf(stderr, "Invalid listen IP\n");
		exit_cleanup();
	}

	printf("batch_epoll_ctl() testing\n");
	ret = syscall_batcher_create(&b, NULL, NULL);
	if (ret < 0) {
		printf("load syscall-batcher failed: %s\n", strerror(-ret));
		exit(0);
	}
	test_epoll_ctl(b);

#if 0
	printf("batch_accept4() testing %s:%d\n", param_listenip, param_port);
	test_accept4(b, serverfd);
#endif
	syscall_batcher_free(b);
	return EXIT_SUCCESS;
}

int init_server(struct in_addr ip, uint16_t port, int cpu)
{
	struct linger linger;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int serverfd;

	/* Open the socket */
	if ((serverfd =
	     socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1) {
		perror("Unable to open socket");
		exit_cleanup();
	}

	/* Close connections quickly (RST instead of FIN) */
	linger.l_onoff = 1;
	linger.l_linger = 0;
	if (setsockopt
	    (serverfd, SOL_SOCKET, SO_LINGER, &linger,
	     sizeof(linger)) == -1) {
		perror("Unable to set socket linger option");
		exit_cleanup();
	}

	/* Configure address parameters for binding */
	memset(&addr, 0, addrlen);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr = ip;

	/* Bind the socket */
	if (bind(serverfd, (struct sockaddr *) &addr, addrlen) == -1) {
		perror("Unable to bind socket");
		exit_cleanup();
	}

	/* Start listening for client connections */
	if (listen(serverfd, 1024) != 0) {
		perror("Cannot listen for client connections");
		exit_cleanup();
	}

	return serverfd;
}

