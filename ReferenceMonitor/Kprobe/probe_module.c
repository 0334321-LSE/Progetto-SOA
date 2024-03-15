#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/printk.h>      
#include <linux/file.h>
#include <linux/version.h>
#include "../reference_monitor.h"


#define MODNAME "PROB-MOD"
MODULE_AUTHOR("Luca Saverio Esposito <lucasavespo17@gmail.com>");
MODULE_DESCRIPTION("This module install kprobe on sys_openat \
and check if black-listed path is opened in write mode");

//what function to hook depending on the system call architecture 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define target_func "__x64_sys_openat"
#else
#define target_func "sys_openat"
#endif 
// #define target_func "do_sys_open"

/*
static int handler_pre(struct kprobe *p, struct pt_regs *regs){
    int fd; 
    struct file *file;
    char* path;

    // Check if the module is OFF or REC-OFF, in that case doesn't need to check access
    if(monitor->state == 0 || monitor->state == 1)
        return 0;
    
    fd = regs_return_value(regs);
    printk("%s:file descriptor:  %d\n", MODNAME, fd);
    file = fget(fd);
     if (!file) {
        printk("%s:Failed to get struct file from file descriptor \n", MODNAME);
        return 0;
    }

    // Obtains file path
    if (file->f_path.dentry) {
        path = kmalloc(PATH_MAX, GFP_KERNEL);
    
        if (path)
            dentry_path_raw(file->f_path.dentry, path, PATH_MAX);
        else{
            printk("%s:Failed locate memory for file path \n", MODNAME);
            fput(file);
            return 0;
        }
    }    
    
    printk("%s: Flags: %d \n", MODNAME,file->f_flags);
    printk("%s: File path: %s \n", MODNAME,path);

    // Check if the file is opened WRITE-ONLY or READ-WRITE
    if (file->f_flags & O_WRONLY || file->f_flags & O_RDWR){
        // Check if file is protected
        printk("%s: File path: %s \n", MODNAME,path);

        if (file_in_protected_paths(path)){
            // ADD WRITE-REPORT ON LOG FILE
            printk("%s: Access on %s blocked correctly \n", MODNAME,path);
            fput(file);
            return -EACCES; // Error
        }
    }

    fput(file);
    return 0;
}
*/

static int handler_pre(struct kprobe *p, struct pt_regs *regs){
    
    char __user *pathname;
    unsigned int flags;

    // Check if the module is OFF or REC-OFF, in that case doesn't need to check access
    if(monitor->state == 0 || monitor->state == 1)
        return 0;
    
    // Ottieni il percorso del file passato come parametro alla system call
    pathname = (char __user *)regs->si; // Il percorso del file è generalmente nel registro si

    // Ottieni i flag di apertura del file passati come parametro alla system call
    flags = (unsigned int)regs->di; // I flag di apertura del file sono generalmente nel registro di

    
    printk("%s: Flags: %d \n", MODNAME,flags);
    printk("%s: File path: %s \n", MODNAME,pathname);

    // Check if the file is opened WRITE-ONLY or READ-WRITE
    if (flags & O_WRONLY || flags & O_RDWR){
        // Check if file is protected
        printk("%s: File path: %s \n", MODNAME,pathname);

        if (file_in_protected_paths(pathname)){
            // ADD WRITE-REPORT ON LOG FILE
            printk("%s: Access on %s blocked correctly \n", MODNAME,pathname);
            return -EACCES; // Error
        }
    }

    return 0;
}

/*
static int handler_pre_filpOpen(struct kprobe *p, struct pt_regs *regs){

    const char __user *filename = (const char __user *)regs->di; // Ottieni il nome del file
    int flags = (int)regs->si; // Ottieni i flag di apertura
    char* kfilename;
   
    printk("%s: Flags: %d \n", MODNAME,flags);
    printk("%s: Filename: %s \n", MODNAME,filename);
    // Check if the module is OFF or REC-OFF, in that case doesn't need to check access
    if(monitor->state == 0 || monitor->state == 1)
        return 0;
    
    // Alloca memoria per il nome del file
    kfilename = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kfilename) {
        printk("%s: Failed to allocate memory for filename\n", MODNAME);
        return 0; 
    }

    // Copia il nome del file dalla memoria utente alla memoria kernel
    if (strncpy_from_user(kfilename, filename, PATH_MAX - 1) < 0) {
       printk("%s: Failed to copy filename from user space\n", MODNAME);
        kfree(kfilename);
        return 0; 
    }

    // Verifica se i permessi di apertura includono la possibilità di scrivere
    if (flags & O_WRONLY || flags & O_RDWR) {
        printk("%s: Filename: %s \n", MODNAME,kfilename);
         // Check if file is protected
        if (file_in_protected_paths(monitor, kfilename)){
            // ADD WRITE-REPORT ON LOG FILE
            printk("%s: Access on %s blocked correctly \n", MODNAME, kfilename);
            kfree(kfilename);
            return -EPERM; // Error
        }
    }

    kfree(kfilename);
    return 0;
}
*/
static struct kprobe kp = {
    .symbol_name = target_func,
    .pre_handler = handler_pre,
};

static int __init kprobe_init(void)
{
    int ret;

    ret = register_kprobe(&kp);
  
    if (ret < 0) {
        printk("%s: Failed to register kprobe: %d\n", MODNAME, ret);
        return ret;
    }
    
    printk("%s: Kprobe registered \n",MODNAME);
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk("%s: Kprobe unregistered\n",MODNAME);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
