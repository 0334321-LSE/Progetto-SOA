cmd_/media/sf_shared-dir/Progetto/ReferenceMonitor/the_usctm.mod := printf '%s\n'   ./LinuxSCTFinder/usctm.o ./LinuxSCTFinder/lib/vtpmo.o | awk '!x[$$0]++ { print("/media/sf_shared-dir/Progetto/ReferenceMonitor/"$$0) }' > /media/sf_shared-dir/Progetto/ReferenceMonitor/the_usctm.mod