#Il nome del modulo deve esser diverso dal sorgente
obj-m += the_rm.o  # Prima il modulo che definisce e esporta la variabile monitor
obj-m += the_usctm.o

the_rm-objs := rm_module.o
the_usctm-objs := ./LinuxSCTFinder/usctm.o ./LinuxSCTFinder/lib/vtpmo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
