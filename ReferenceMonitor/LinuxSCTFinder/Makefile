obj-m += the_usctm.o
the_usctm-objs := usctm.o /lib/vtpmo.o ../reference_monitor.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	sudo insmod the_usctm.ko

