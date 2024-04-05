obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install: 
	sudo insmod singlefilefs.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	
mount-fs: install create-fs
		if [ ! -d "/mnt/monitor-fs/" ]; then \
        sudo mkdir "/mnt/monitor-fs/"; \
    else \
        echo "/mnt/monitor-fs/ already exists."; \
    fi

	sudo mount -o loop -t singlefilefs image /mnt/monitor-fs/
