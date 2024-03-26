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
#include <linux/namei.h>
#include <linux/dcache.h>

#include "open_flags.h"

#include "../reference_monitor.h"
#define MODNAME "RPROB-MOD"

MODULE_AUTHOR("Luca Saverio Esposito <lucasavespo17@gmail.com>");
MODULE_DESCRIPTION("This module install kretprobe do_filp_open \
and check if black-listed path is opened in write mode. \
PAY ATTENTION: The module is developed for x86-64 and x86-32, it relies on the specific system call calling convention of this architectures.");

#define open_func "do_filp_open"
#define openat_func "path_openat"

#define unlink_func "security_path_unlink"

#define rmdir_func "security_path_rmdir"

#define rename_func "security_path_rename"

#define mkdir_func "security_path_mkdir"

static unsigned long open_audit_counter = 0;//just to audit how many times open_krobe has been called
static unsigned long unlink_audit_counter = 0;//just to audit how many times unlink_krobe has been called
static unsigned long rmdir_audit_counter = 0;//just to audit how many times rmdir_krobe has been called
static unsigned long rename_audit_counter = 0;//just to audit how many times rename_krobe has been called
static unsigned long mkdir_audit_counter = 0;//just to audit how many times mkdir_krobe has been called

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

int register_hook(struct kretprobe *the_probe, char * the_func){
    int ret;
    ret = register_kretprobe(the_probe);
	if (ret < 0) {
        printk("%s: Failed to register kprobe: %d\n", MODNAME, ret);
		return ret;
	}
    printk("%s: Kretprobe registered on %s \n",MODNAME,the_func);
	
	return 0;
}

/* PATH OPENAT HANDLERS
static int openat_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    // path openat pre handler

    struct nameidata * nd;
    struct open_flags * op_flags;
    struct inode * inode;
    struct filename * pathname_struct;
    const char *pathname;
    int flags;

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;


    atomic_inc((atomic_t*)&open_audit_counter);

    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
   
    //path_openat(struct nameidata *nd, const struct open_flags *op, unsigned flags)

    // nameidata is the first parameter, it contains the inode and filename.
    nd = (struct nameidata *) the_regs->di; 
    inode = nd->inode;
    pathname_struct = nd->name;
    pathname = pathname_struct->name;

    // open_flag is the second parameter
    op_flags = (struct open_flags *) the_regs->si; 
    flags = op_flags->open_flag;
    
    // Check if the file is opened WRITE-ONLY or READ-WRITE
    if (flags & O_WRONLY || flags & O_RDWR){
        
        // Check if file is protected
        if (inode_in_protected_paths(inode->i_ino)){
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
*/

// OPEN HANDLERS 
static int open_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    // do_filp_open pre handler

    const char *pathname;
    struct filename * pathname_struct;
    struct open_flags * op_flags;
    int flags;

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;


    atomic_inc((atomic_t*)&open_audit_counter);

    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
    /* do filp open definition: 
    struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);*/

    // Pathname is the second parameter
    pathname_struct = (struct filename *) the_regs->si; 
    pathname = pathname_struct->name;

    // op is the third parameter
    op_flags = (struct open_flags *) the_regs->dx; 
    flags = op_flags->open_flag;
    
    // Check if the file is opened WRITE-ONLY or READ-WRITE
    if (flags & O_WRONLY || flags & O_RDWR){
        
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

static int open_post_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs) {
    the_regs->ax = -1; 
    printk("%s: Open blocked\n", MODNAME);

    return 0;
}


//----------------------------

/* UNLINK HANDLERS */
static int unlink_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    struct dentry *dentry;
    struct inode *target; 

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;

    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
    
    /*int security_path_unlink(const struct path *dir, struct dentry *dentry)*/
    //Dentry is the second parameter, from this can be retrieved the inode of the file.
    dentry = (struct dentry*) the_regs->si;
    target = dentry->d_inode;
    atomic_inc((atomic_t*)&unlink_audit_counter);

    if(inode_in_protected_paths(target->i_ino)){
        printk("%s: Unlink on %s blocked correctly \n", MODNAME,dentry->d_name.name);
        return 0;
    }

end:
    return 1;
}

static int unlink_post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    the_regs->ax = -1;
    printk("%s: Unlink blocked\n", MODNAME);

    return 0;
}

//----------------------------



// RMDIR HANDLERS
static int rmdir_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    struct dentry *dentry;
    struct inode *target; 

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;
        
    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
    /* int security_path_rmdir(const struct path *dir, struct dentry *dentry)*/

    // dentry is the second parameter, is associated to directory to be removed
    dentry = (struct dentry *) the_regs->si;
    target = dentry->d_inode;

    //dentry is the second parameter
    atomic_inc((atomic_t*)&rmdir_audit_counter);

    if(inode_in_protected_paths(target->i_ino)){
        // ADD TO LOG
        printk("%s: Rmdir on %s blocked correctly \n", MODNAME,dentry->d_name.name);
        return 0;
    }

end:
    return 1;
}

static int rmdir_post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    the_regs->ax = -1;
    printk("%s: Rmdir blocked\n", MODNAME);

    return 0;
}

//----------------------------


// RENAME HANDLERS
static int rename_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    struct dentry *dentry;
    struct inode *target; 

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;
        
    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
    /* int security_path_rename(const struct path *old_dir, struct dentry *old_dentry,
			 const struct path *new_dir, struct dentry *new_dentry,	unsigned int flags)*/

    // old_dentry: the old file is the second parameter
    dentry = (struct dentry *) the_regs->si;
    target = dentry->d_inode;

    atomic_inc((atomic_t*)&rename_audit_counter);

    if(inode_in_protected_paths(target->i_ino)){
        // ADD TO LOG
        printk("%s: Rename on %s blocked correctly \n", MODNAME,dentry->d_name.name);
        return 0;
    }

end:
    return 1;
}

static int rename_post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    the_regs->ax = -1;
    printk("%s: Rename blocked\n", MODNAME);

    return 0;
}

//----------------------------

// MKDIR HANDLERS
static int mkdir_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    struct dentry *dentry;
    struct inode *target; 
    struct path *path;
    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;
        
    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
    /* int security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)*/

    // path is the parent directory (the one to check) is the first parameter
    path = (struct path *) the_regs->di;
    dentry = path->dentry;
    target = dentry->d_inode;

    atomic_inc((atomic_t*)&rename_audit_counter);

    if(inode_in_protected_paths(target->i_ino)){
        // ADD TO LOG
        printk("%s: Mkdir on %s blocked correctly \n", MODNAME,dentry->d_name.name);
        return 0;
    }

end:
    return 1;
}

static int mkdir_post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    the_regs->ax = -1;
    printk("%s: Mkdir blocked\n", MODNAME);

    return 0;
}

//----------------------------


static struct kretprobe open_retprobe = {
    .kp.symbol_name = open_func, // Nome della funzione da intercettare
    .handler = open_post_handler, // Gestore dell'uscita della kretprobe
    .entry_handler = open_pre_handler, // Gestore dell'entrata della kretprobe
    .maxactive = -1 // Numero massimo di kretprobes attive, -1 per il valore predefinito
};


static struct kretprobe unlink_retprobe = {
    .kp.symbol_name = unlink_func, // Nome della funzione da intercettare
    .handler = unlink_post_handler, // Gestore dell'uscita della kretprobe
    .entry_handler = unlink_pre_handler, // Gestore dell'entrata della kretprobe
    .maxactive = -1 // Numero massimo di kretprobes attive, -1 per il valore predefinito
};

static struct kretprobe rmdir_retprobe = {
    .kp.symbol_name = rmdir_func, // Nome della funzione da intercettare
    .handler = rmdir_post_handler, // Gestore dell'uscita della kretprobe
    .entry_handler = rmdir_pre_handler, // Gestore dell'entrata della kretprobe
    .maxactive = -1 // Numero massimo di kretprobes attive, -1 per il valore predefinito
};

static struct kretprobe rename_retprobe = {
    .kp.symbol_name = rename_func, // Nome della funzione da intercettare
    .handler = rename_post_handler, // Gestore dell'uscita della kretprobe
    .entry_handler = rename_pre_handler, // Gestore dell'entrata della kretprobe
    .maxactive = -1 // Numero massimo di kretprobes attive, -1 per il valore predefinito
};

static struct kretprobe mkdir_retprobe = {
    .kp.symbol_name = mkdir_func, // Nome della funzione da intercettare
    .handler = mkdir_post_handler, // Gestore dell'uscita della kretprobe
    .entry_handler = mkdir_pre_handler, // Gestore dell'entrata della kretprobe
    .maxactive = -1 // Numero massimo di kretprobes attive, -1 per il valore predefinito
};

static int hook_init(void) {
 
    // OPEN
    /*if ( register_hook(&open_retprobe, openat_func)  < 0)
        return -1;*/
    // UNLINK
    if ( register_hook(&unlink_retprobe, unlink_func) < 0)
        return -1;
    
    // RMDIR
    if ( register_hook(&rmdir_retprobe, rmdir_func) < 0)
        return -1;

    // RENAME
    if ( register_hook(&rename_retprobe, rename_func) < 0)
        return -1;

    // RENAME
    if ( register_hook(&mkdir_retprobe, mkdir_func) < 0)
        return -1;
    
    return 0;
}



static void  hook_exit(void) {

	//unregister_kretprobe(&open_retprobe);
    unregister_kretprobe(&unlink_retprobe);
	unregister_kretprobe(&rmdir_retprobe);
    unregister_kretprobe(&rename_retprobe);
    unregister_kretprobe(&mkdir_retprobe);



    printk("%s: %s hook invoked %lu times\n",MODNAME, openat_func ,open_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, unlink_func ,unlink_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, rmdir_func ,rmdir_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, rename_func ,rename_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, mkdir_func ,mkdir_audit_counter);

    printk("%s: Kretprobes unregistered\n",MODNAME);

}

module_init(hook_init);
module_exit(hook_exit);
MODULE_LICENSE("GPL");
