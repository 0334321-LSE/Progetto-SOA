#Il nome del modulo deve esser diverso dal sorgente
obj-m += the_rm.o
obj-m += the_usctm.o
obj-m += the_retprobe.o
#obj-m += singlefilefs.o

the_rm-objs := /Monitor/rm_module.o reference_monitor.o
the_usctm-objs := /LinuxSCTFinder/usctm.o /LinuxSCTFinder/lib/vtpmo.o reference_monitor.o
the_retprobe-objs := /Kretprobes/retprobe_module.o reference_monitor.o 
#singlefilefs-objs += /singlefile-FS/singlefilefs_src.o /singlefile-FS/file.o /singlefile-FS/dir.o

ifdef SYMLINK
    ccflags-y += -DSYMLINK
endif

ifdef LINK
    ccflags-y += -DLINK
endif

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/singlefile-FS modules
	
	gcc ./singlefile-FS/singlefilemakefs.c -o ./singlefile-FS/singlefilemakefs
	gcc ./user/client.c -o client

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C $(PWD)/singlefile-FS clean


install:
	@echo "Installing modules..."; 
	@if echo "$(PASSWORD)" | grep -q ' '; then \
		echo "Error: Password cannot contain spaces."; \
		exit 1; \
	fi
	sudo insmod the_rm.ko password="$(PASSWORD)"
	sudo insmod the_usctm.ko
	sudo insmod the_retprobe.ko
	@make -C singlefile-FS mount-fs
	echo "Modules installed."
	sudo ./client

# Remove all installed modules
uninstall:
	echo "Removing modules"
	sudo rmmod the_retprobe 
	echo "probe removed"
	sudo rmmod the_usctm 
	echo "usctm removed"
	sudo rmmod the_rm 
	echo "rm removed"
#sudo rmmod singlefilefs
#echo "singlefilefs removed"


	