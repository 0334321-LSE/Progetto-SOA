#include <unistd.h>
int main(int argc, char** argv){
    syscall(134,"REC-OFF","soa");
    syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt","soa",1);
    syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test","soa",1);
    syscall(174,"/home/xave/Desktop/Prova","soa",1);

    return 0;
}

