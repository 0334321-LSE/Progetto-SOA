#include <unistd.h>
int main(int argc, char** argv){
    syscall(134,"REC-OFF","abc");
    syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt","abc",0);
    syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test","abc",0);
    syscall(174,"/home/xave/Desktop/Prova/test.txt","abc",0);

    syscall(182,"abc");
    syscall(134,"ON","abc");
    return 0;
    //syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt","abc",2);
    //syscall(174,"/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt","abc",1);
}

