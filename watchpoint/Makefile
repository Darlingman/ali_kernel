obj-m:=wp.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean

run: all
	insmod wp.ko
	rmmod wp.ko
	dmesg -c
