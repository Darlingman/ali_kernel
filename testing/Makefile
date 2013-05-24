obj-m := jl.o

KDIR=../build.5u

all:
	make -C ${KDIR} M=`pwd` modules

clean:
	make -C ${KDIR} M=`pwd` clean

test:
	insmod jl.ko
	rmmod jl.ko
	dmesg -c
