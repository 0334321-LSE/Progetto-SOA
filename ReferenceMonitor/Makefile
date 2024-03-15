#Il nome del modulo deve esser diverso dal sorgente
obj-m += the_rm.o
obj-m += the_usctm.o
obj-m += the_probe.o

the_rm-objs := rm_module.o
the_usctm-objs := ./LinuxSCTFinder/usctm.o ./LinuxSCTFinder/lib/vtpmo.o ./reference_monitor.o
the_probe-objs := ./Kprobe/probe_module.o ./reference_monitor.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
