#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/printk.h>    
#include <linux/spinlock.h>  
#include <linux/file.h>
#include <linux/version.h>
#include "open_flags.h"
#include "../reference_monitor.h"


#define MODNAME "PROB-MOD"
MODULE_AUTHOR("Luca Saverio Esposito <lucasavespo17@gmail.com>");
MODULE_DESCRIPTION("This module install kprobe on sys_openat or do_filp_open (different deep level)\
and check if black-listed path is opened in write mode. \
Define SYS_OPENAT to work on sys_openat, otherwise it intercepts do_filp_open. \
PAY ATTENTION: The module is developed for x86-64 and x86-32, it relies on the specific system call calling convention of this architectures.");

#define SYS_OPENAT

//what function to hook, depending on the system call architecture 
#ifdef SYS_OPENAT
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)    
    #define target_func "__x64_sys_openat"
    #else
    #define target_func "sys_openat"
    #endif 
#else
    #define target_func "do_filp_open"
#endif 

//where to look at when searching system call parmeters
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define get(regs)	regs = (struct pt_regs*)the_regs->di;
#else
#define get(regs)	regs = the_regs;
#endif

static unsigned long open_audit_counter = 0;//just to audit how many times krobe has been called

void print_flag(int flags){
// Stampa le flags di apertura del file
    if (flags & O_RDONLY)
        printk("%s: Flags O_RDONLY \n", MODNAME);
    if (flags & O_WRONLY)
        printk("%s: Flags O_WRONLY \n", MODNAME);
    if (flags & O_RDWR)
        printk("%s: Flags O_RDWR \n", MODNAME);
    if (flags & O_CREAT)
        printk("%s: Flags O_CREAT \n", MODNAME);
    if (flags & O_TRUNC)
        printk("%s: Flags O_TRUNC \n", MODNAME);
}

#ifdef SYS_OPENAT
    static int handler_pre(struct kprobe *p, struct pt_regs *the_regs){
        
        char *pathname;
        unsigned int flags;
        struct pt_regs * regs;

        // Check if the module is OFF or REC-OFF, in that case doesn't need to check access
        if(monitor->state == 0 || monitor->state == 1)
            return 0;
        
        atomic_inc((atomic_t*)&open_audit_counter);
        get(regs);//get the actual address of the CPU image seen by the system call (or its wrapper)

        // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
        /* Openat definition: int openat(int fildes, const char *path, int oflag, mode_t mode );*/

        // Pathname is the second parameter
        pathname = (char __user*)regs->si;
        // Copy from user space to kernel space
  //      if (copy_from_user(pathname, (char __user*)regs->si, PATH_MAX)) {
    //        return -EFAULT;
//        }

        

        // Flag is the third parameter
        flags = (unsigned int)regs->dx; // I flag di apertura del file sono generalmente nel registro di

        // Check if the file is opened WRITE-ONLY or READ-WRITE
        if (flags & O_WRONLY || flags & O_RDWR){
            // Check if file is protected
            if (file_in_protected_paths(pathname)){
                // ADD WRITE-REPORT ON LOG FILE
                printk("%s: Access on %s blocked correctly \n", MODNAME,pathname);
                print_flag(flags);
                regs->dx = O_RDONLY;
                //return -EPERM; // Error
            }
        }

        return 0;
    }
#else
    static int handler_pre_filp(struct kprobe *p, struct pt_regs *the_regs){
        
        char *pathname;
        struct filename * pathname_struct;
        struct open_flags * op_flags;
        struct pt_regs * regs;
        int flags;

        // Check if the module is OFF or REC-OFF, in that case doesn't need to check access
        if(monitor->state == 0 || monitor->state == 1)
            return 0;
        
        atomic_inc((atomic_t*)&audit_counter);
        get(regs);//get the actual address of the CPU image seen by the system call (or its wrapper)

        // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
        /* do filp open definition: 
        struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);*/

        // Pathname is the second parameter
        pathname_struct = (struct filename *)regs->si; 
        pathname = (char *) pathname_struct->name;

        // op is the third parameter
        op_flags = (struct open_flags *)regs->dx; 
        flags = (unsigned int) op_flags->open_flag;

        // Check if the file is opened WRITE-ONLY or READ-WRITE
        if (flags & O_WRONLY || flags & O_RDWR){
            // Check if file is protected
            if (file_in_protected_paths(pathname)){
                // ADD WRITE-REPORT ON LOG FILE
                printk("%s: Access on %s blocked correctly \n", MODNAME,pathname);
                print_flag(flags);

                //return -EPERM; // Error
            }
        }

        return 0;
    }
#endif

static struct kprobe kp = {
    .symbol_name = open_func,
    #ifdef SYS_OPENAT
        .pre_handler = (kprobe_pre_handler_t) handler_pre,
    #else 
        .pre_handler = (kprobe_pre_handler_t) handler_pre_filp,
    #endif
};

static int __init kprobe_init(void)
{
    int ret;

    ret = register_kprobe(&kp);
  
    if (ret < 0) {
        printk("%s: Failed to register kprobe: %d\n", MODNAME, ret);
        return ret;
    }
    #ifdef SYS_OPENAT
        printk("%s: Kprobe registered on sys_openat \n",MODNAME);
    #else 
        printk("%s: Kprobe registered on do_filp_open \n",MODNAME);
    #endif
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    #ifdef SYS_OPENAT
        printk("%s: sys_openat hook invoked %lu times\n",MODNAME, open_audit_counter);
    #else
        printk("%s: do_filp_open hook invoked %lu times\n",MODNAME, audit_counter);
    #endif
    printk("%s: Kprobe unregistered\n",MODNAME);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
