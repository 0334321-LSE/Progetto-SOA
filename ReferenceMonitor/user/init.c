#include <unistd.h>
int main(int argc, char** argv){
    syscall(134,"REC-OFF","soa");
    syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt","soa",0);
    syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test","soa",0);
    syscall(174,"/home/xave/Desktop/Prova","soa",0);

    //syscall(182,"soa");
    syscall(134,"ON","soa");
    return 0;
    //syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt","abc",2);
    //syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt","abc",1);
}

