#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/printk.h>    
#include <linux/spinlock.h>  
#include <linux/file.h>
#include <linux/version.h>
#include <linux/path.h> 
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>

#include "open_flags.h"
#include "../reference_monitor.h"


#define MODNAME "RPROB-MOD"
MODULE_AUTHOR("Luca Saverio Esposito <lucasavespo17@gmail.com>");
MODULE_DESCRIPTION("This module install kretprobe do_filp_open \
and check if black-listed path is opened in write mode. \
PAY ATTENTION: The module is developed for x86-64 and x86-32, it relies on the specific system call calling convention of this architectures.");

#define target_func "do_filp_open"
 

static unsigned long audit_counter = 0;//just to audit how many times krobe has been called

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

void get_abs_path(int dfd){
    
    char *tmp = (char*)__get_free_page(GFP_ATOMIC);
    struct fd fd;
    struct file *dir_file;
    struct path pwd_path;
    struct dentry *dentry;
    char *absolute_path = NULL;

    // Ottenere il dentry per la directory di lavoro corrente
    if (dfd == AT_FDCWD) {
        pwd_path = current->fs->pwd;
        dentry = pwd_path.dentry;
    } else {
        // Ottieni il file associato al directory file descriptor
        fd = fdget(dfd);
        if (! fd.file) {
            // Gestisci l'errore se il file non è valido
            printk("%s impossibile ottenere il file associato al directory file descriptor %d\n", MODNAME, dfd);
            return;
        }
        dir_file = fd.file;

        // Ottieni il percorso assoluto associato al file
        absolute_path = d_path(&dir_file->f_path, tmp, PATH_MAX);
        printk("%s: Path %s\n", MODNAME, absolute_path);

        // Rilascia la struttura file
        fdput(fd);

        return;
    }

    // Convertire il dentry in un percorso assoluto
    absolute_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (absolute_path) {
        char *path_ptr = dentry_path_raw(dentry, absolute_path, PATH_MAX);
        if (IS_ERR(path_ptr)) {
            // Gestione dell'errore
            printk("%s erorre path phtr\n", MODNAME);
            kfree(absolute_path);
            absolute_path = NULL;
        }
        printk("%s: Path %s\n", MODNAME, path_ptr);
    }
   

    return;


}

static int pre_handler(struct kprobe *p, struct pt_regs *the_regs){
    // do_filp_open pre handler

    const char *pathname;
    struct filename * pathname_struct;
    struct open_flags * op_flags;
    int flags;
    int dfd;

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;


    atomic_inc((atomic_t*)&audit_counter);

    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
    /* do filp open definition: 
    struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);*/

    // dfd is the first parameter
    dfd = (int) the_regs->di;

    // Pathname is the second parameter
    pathname_struct = (struct filename *) the_regs->si; 
    pathname = pathname_struct->name;

    // op is the third parameter
    op_flags = (struct open_flags *) the_regs->dx; 
    flags = op_flags->open_flag;
    
  

    // Check if the file is opened WRITE-ONLY or READ-WRITE
    if (flags & O_WRONLY || flags & O_RDWR){
        get_abs_path(dfd);
        // Check if file is protected
        if (file_in_protected_paths(pathname)){
            // ADD WRITE-REPORT ON LOG FILE
            printk("%s: Access on %s blocked correctly \n", MODNAME,pathname);
            //print_flag(flags);
            //The kretprobe post handler should be executed: the access must be blocked
            return 0;
        }

    } 

end: 
    // Doesn't execute the post handler, the access is legit
    return 1;
}

static int post_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs) {
    the_regs->ax = -1; 
    printk("%s: Modified return value in post handler\n", MODNAME);

    return 0;
}

static struct kretprobe retprobe;  

static int hook_init(void) {

	int ret;
    
	retprobe.kp.symbol_name = target_func;
	retprobe.handler = (kretprobe_handler_t)post_handler;
	retprobe.entry_handler = (kretprobe_handler_t)pre_handler;
	retprobe.maxactive = -1; //lets' go for the default number of active kretprobes manageable by the kernel

	ret = register_kretprobe(&retprobe);
	if (ret < 0) {
        printk("%s: Failed to register kprobe: %d\n", MODNAME, ret);
		return ret;
	}
    printk("%s: Kretprobe registered on %s \n",MODNAME,target_func);
	
	return 0;
}

static void  hook_exit(void) {

	unregister_kretprobe(&retprobe);

    printk("%s: %s hook invoked %lu times\n",MODNAME, target_func ,audit_counter);
    printk("%s: Kretprobe unregistered\n",MODNAME);

}

module_init(hook_init);
module_exit(hook_exit);
MODULE_LICENSE("GPL");
