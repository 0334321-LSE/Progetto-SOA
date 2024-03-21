echo "Installing modules"
make clean
make
sudo insmod the_rm.ko
sudo insmod the_usctm.ko
#sudo insmod the_probe.ko
sudo insmod the_retprobe.ko
