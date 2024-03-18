#include <unistd.h>
int main(int argc, char** argv){
    syscall(134,"REC-OFF","abc");
    syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt","abc",1);
    return 0;
}

