obj-m	:=	syscall-batcher.o
syscall-batcher-objs := main.o

KERNEL_DEVEL_DIR=../build.5u

CFLAGS_TESTSUITE=-fno-strict-aliasing -g -O2 -Wall -DB_SYSCALL=1

test-suite:
	gcc -c ${CFLAGS_TESTSUITE}  -I. -DDEBUG=0 b_syscall.c	-c
	gcc -c ${CFLAGS_TESTSUITE} -I. test_b_syscall.c	-c
	gcc -c ${CFLAGS_TESTSUITE} -I. test_r_syscall.c	-c
	gcc -c ${CFLAGS_TESTSUITE} -I. test_batch.c		-c
	gcc ${CFLAGS_TESTSUITE} b_syscall.o test_b_syscall.o -o test_b_syscall
	gcc ${CFLAGS_TESTSUITE} 	     test_r_syscall.o -o test_r_syscall
	gcc ${CFLAGS_TESTSUITE} b_syscall.o test_batch.o -o	 test_batch

ko:
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` modules

clean:
	rm -f *.o test_?_syscall *~ test_batch
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` clean

scpko:
	scp * root@10.32.228.115:/root/microb/syscall-batcher

scp:
	scp * root@10.232.97.4:/home/li/kernels/linux-2.6.32-279.9.1.netdev/park/syscall-batcher/
