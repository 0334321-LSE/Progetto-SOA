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

#define open_func "vfs_open"
#define mayopen_func "may_open"

#define unlink_func "security_path_unlink"

#define rmdir_func "security_path_rmdir"

#define rename_func "security_path_rename"

#define mkdir_func "security_path_mkdir"

#define create_func "security_inode_create"

//#define SYMLINK

#ifdef SYMLINK
    #define symlink_func "security_path_symlink"
#endif

static unsigned long open_audit_counter = 0;//just to audit how many times open_krobe has been called
static unsigned long unlink_audit_counter = 0;//just to audit how many times unlink_krobe has been called
static unsigned long rmdir_audit_counter = 0;//just to audit how many times rmdir_krobe has been called
static unsigned long rename_audit_counter = 0;//just to audit how many times rename_krobe has been called
static unsigned long mkdir_audit_counter = 0;//just to audit how many times mkdir_krobe has been called
static unsigned long create_audit_counter = 0;//just to audit how many times mkdir_krobe has been called

#ifdef SYMLINK
static unsigned long symlink_audit_counter = 0;//just to audit how many times symlink_krobe has been called
#endif

// Usefull for debugging
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

/* VFSOPEN HANDLERS */
static int vfsopen_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    // vfsopen pre handler

    struct path* path;
    struct dentry* dentry;
    struct inode * inode;
    struct file * file;
    const char *pathname;
    int flags;

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;



    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
   
    //int vfs_open(const struct path *path, struct file *file)
    // path is the first parameter, it contains the dentry of the file.
    path = (struct path *) the_regs->di; 
    dentry = path->dentry;
    inode = dentry->d_inode;
    pathname = dentry->d_name.name;

    // flags is the fourth parameter 
    file = (struct file*) the_regs->si;
    flags = file->f_flags;


    // Check if the file is opened WRITE-ONLY or READ-WRITE
    if (flags & O_WRONLY || flags & O_RDWR || flags & O_CREAT || flags & O_APPEND || flags & O_TRUNC){
        // Check if file is protected
        if (inode_in_protected_paths(inode->i_ino)){
            // ADD WRITE-REPORT ON LOG FILE
            printk("%s: Access on %s blocked correctly \n", MODNAME,pathname);
            atomic_inc((atomic_t*)&open_audit_counter);

            //print_flag(flags);
            //The kretprobe post handler should be executed: the access must be blocked
            return 0;
        }

    } 

end: 
    // Doesn't execute the post handler, the access is legit
    return 1;
}

/* MAY_OPEN HANDLERS */
static int mayopen_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    // mayopen pre handler

    struct path* path;
    struct dentry* dentry;
    struct inode * inode;
    const char *pathname;
    int flags;

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;


    atomic_inc((atomic_t*)&open_audit_counter);

    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
   
    //int may_open(struct mnt_idmap *idmap, const struct path *path, int acc_mode, int flag)
    // path is the second parameter, it contains thedentry.
    path = (struct path *) the_regs->si; 
    dentry = path->dentry;
    inode = dentry->d_inode;
    pathname = dentry->d_name.name;

    // flags is the fourth parameter 
    flags = (int) the_regs->r10;


    // Check if the file is opened WRITE-ONLY or READ-WRITE
    if (flags & O_WRONLY || flags & O_RDWR || flags & O_CREAT || flags & O_APPEND || flags & O_TRUNC){
        // Check if file is protected
        if (inode_in_protected_paths(inode->i_ino)){
            // ADD WRITE-REPORT ON LOG FILE
            printk("%s: Access on %s blocked correctly \n", MODNAME,pathname);
            print_flag(flags);
            //The kretprobe post handler should be executed: the access must be blocked
            return 0;
        }

    } 

end: 
    // Doesn't execute the post handler, the access is legit
    return 1;
}

static int open_post_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs) {
    the_regs->ax = -EACCES; 
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

    if(inode_in_protected_paths(target->i_ino)){
        atomic_inc((atomic_t*)&unlink_audit_counter);

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



    if(inode_in_protected_paths(target->i_ino)){
        // ADD TO LOG   
        atomic_inc((atomic_t*)&rmdir_audit_counter);
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

    

    if(inode_in_protected_paths(target->i_ino)){
        // ADD TO LOG
        atomic_inc((atomic_t*)&rename_audit_counter);
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


    if(inode_in_protected_paths(target->i_ino)){
        // ADD TO LOG
        atomic_inc((atomic_t*)&mkdir_audit_counter);
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


// CREATE HANDLERS
static int create_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
   
    struct inode *target; 
    struct dentry * dentry;
    struct dentry * parent_dentry;

    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
     if(monitor->state == 0 || monitor->state == 1)
        goto end;
        
    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
    /* int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) */

    // path is the parent directory (the one to check) is the first parameter
    target = (struct inode *) the_regs->di;
    dentry = (struct dentry *) the_regs->si;
    parent_dentry = dentry->d_parent;

    if(inode_in_protected_paths(target->i_ino)){
        // ADD TO LOG
        atomic_inc((atomic_t*)&create_audit_counter);
        printk("%s: Create on %s of %s blocked correctly \n", MODNAME,parent_dentry->d_name.name, dentry->d_name.name);
        return 0;
    }

end:
    return 1;
}

static int create_post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    the_regs->ax = -1;
    printk("%s: create blocked\n", MODNAME);

    return 0;
}

//----------------------------

#ifdef SYMLINK
// SYMLINK HANDLERS
static int symlink_pre_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    struct dentry *dentry;
    struct inode *inode;
    struct path* path;
    const char * old_name;
    // Check if the module is OFF or REC-OFF, in that case doesn't need to execute the post handler
    if(monitor->state == 0 || monitor->state == 1)
        goto end;
        
    // x86-64 syscall calling convention: %rdi, %rsi, %rdx, %r10, %r8 and %r9.
    /* int security_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name)*/

    // old name is the target file path
    old_name = (char *) the_regs->dx;
    atomic_inc((atomic_t*)&symlink_audit_counter);

    if(file_in_protected_paths(old_name)){
        //ADD TO LOG
        printk("%s: Symlink on %s blocked correctly \n", MODNAME,old_name);
        return 0;
    }

end:
    return 1;
}

static int symlink_post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    the_regs->ax = -1;
    printk("%s: Symlink blocked\n", MODNAME);

    return 0;
}

//----------------------------
#endif

static struct kretprobe open_retprobe = {
    .kp.symbol_name = open_func, // Nome della funzione da intercettare
    .handler = open_post_handler, // Gestore dell'uscita della kretprobe
    .entry_handler = vfsopen_pre_handler, // Gestore dell'entrata della kretprobe
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

static struct kretprobe create_retprobe = {
    .kp.symbol_name = create_func, // Nome della funzione da intercettare
    .handler = create_post_handler, // Gestore dell'uscita della kretprobe
    .entry_handler = create_pre_handler, // Gestore dell'entrata della kretprobe
    .maxactive = -1 // Numero massimo di kretprobes attive, -1 per il valore predefinito
};

#ifdef SYMLINK
static struct kretprobe symlink_retprobe = {
    .kp.symbol_name = symlink_func, // Nome della funzione da intercettare
    .handler = symlink_post_handler, // Gestore dell'uscita della kretprobe
    .entry_handler = symlink_pre_handler, // Gestore dell'entrata della kretprobe
    .maxactive = -1 // Numero massimo di kretprobes attive, -1 per il valore predefinito
};
#endif

static int hook_init(void) {
 
    // OPEN
    if ( register_hook(&open_retprobe, open_func)  < 0)
        return -1;

    // UNLINK
    if ( register_hook(&unlink_retprobe, unlink_func) < 0)
        return -1;
    
    // RMDIR
    if ( register_hook(&rmdir_retprobe, rmdir_func) < 0)
        return -1;

    // RENAME
    if ( register_hook(&rename_retprobe, rename_func) < 0)
        return -1;

    // MKDIR
    if ( register_hook(&mkdir_retprobe, mkdir_func) < 0)
        return -1;

    // CREATE
    if ( register_hook(&create_retprobe, create_func) < 0)
        return -1;
    
    #ifdef SYMLINK
    // SYMLINK
    if ( register_hook(&symlink_retprobe, symlink_func) < 0)
        return -1;
    #endif
    return 0;
}



static void  hook_exit(void) {

	unregister_kretprobe(&open_retprobe);
    unregister_kretprobe(&unlink_retprobe);
	unregister_kretprobe(&rmdir_retprobe);
    unregister_kretprobe(&rename_retprobe);
    unregister_kretprobe(&mkdir_retprobe);
    unregister_kretprobe(&create_retprobe);

    #ifdef SYMLINK
        unregister_kretprobe(&symlink_retprobe);
    #endif



    printk("%s: %s hook invoked %lu times\n",MODNAME, open_func ,open_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, unlink_func ,unlink_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, rmdir_func ,rmdir_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, rename_func ,rename_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, mkdir_func ,mkdir_audit_counter);
    printk("%s: %s hook invoked %lu times\n",MODNAME, mkdir_func ,create_audit_counter);

    #ifdef SYMLINK
        printk("%s: %s hook invoked %lu times\n",MODNAME, symlink_func ,symlink_audit_counter);
    #endif

    printk("%s: Kretprobes unregistered\n",MODNAME);

}

module_init(hook_init);
module_exit(hook_exit);
MODULE_LICENSE("GPL");
