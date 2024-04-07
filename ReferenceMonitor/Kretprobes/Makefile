obj-m += the_retprobe.o
the_retprobe-objs := ./retprobe_module.o ../reference_monitor.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	sudo insmod the_retprobe.ko

