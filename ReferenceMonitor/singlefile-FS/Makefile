obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install: 
# Check if the filesystem is already mounted
	@if lsmod | grep -q '^singlefilefs\s'; then \
		echo "Module 'singlefilefs' is already loaded. Skipping installation."; \
	else \
		sudo insmod singlefilefs.ko; \
	fi

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm singlefilemakefs

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	
mount-fs: install create-fs
# Check if the directory '/mnt/monitor-fs/' exists
	@if [ ! -d "/mnt/monitor-fs/" ]; then \
		sudo mkdir -p "/mnt/monitor-fs/"; \
	fi
# Mount the filesystem if it's not already mounted
	@if ! grep -qs '/mnt/monitor-fs' /proc/mounts; then \
		sudo mount -o loop -t singlefilefs image /mnt/monitor-fs/; \
	fi
