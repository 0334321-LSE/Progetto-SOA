/*
* 
* This is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* This module is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* 
* @file rm_module.c 
* @brief An implementation of a Reference Monitor, it checks operation on specified path and) 
*       reports on a log every access.)
* @author Luca Saverio Esposito
*
* @date March 06, 2024
*/

#define MODNAME "REFMON"
#include <linux/module.h>
#include <linux/list.h>
#include <linux/spinlock.h>  
#include <linux/slab.h> 
#include "../reference_monitor.h"  

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Saverio Esposito <lucasavespo17@gmail.com>");
MODULE_DESCRIPTION("Kernel module that implements reference monitor");

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


char *password = NULL;

module_param(password, charp, S_IRUGO); // Define module parameter 'password'
MODULE_PARM_DESC(password, "Password for monitor operation");

struct reference_monitor* monitor;

// Implementazione dell'operazione di inizializzazione del monitor
int reference_monitor_init(void) {
    if (!password || strlen(password)==0) {
        printk("%s: Missing password for monitor init\n", MODNAME);
        return -EINVAL;
    }

    INIT_LIST_HEAD(&monitor->protected_paths);  // Inizializza la lista dei percorsi protetti
    spin_lock_init(&monitor->lock);  // Inizializza lo spinlock

    // Imposta lo stato iniziale del monitor (OFF)
    monitor->state = OFF;
    
    //printk("%s: Password: %s",MODNAME,password);

    password = get_sha(password);

    // Inizializza il campo della password 
    monitor->password = kstrdup(password,GFP_KERNEL);
    
    // printk("%s: Password for monitor init: %s -> %s\n", MODNAME, password,monitor->password);
    if (!monitor->password)
        return -ENOMEM;  // Errore di memoria

    return 0;  // Successo
}

// Implementazione dell'operazione di release del monitor
void reference_monitor_cleanup(void) {
    struct protected_path *entry, *tmp;

    // Acquire lock to work with the list
    spin_lock(&monitor->lock);

    rcu_read_lock();

    // Iterate over the old list and free entries under RCU protection
    list_for_each_entry_safe(entry, tmp, &monitor->protected_paths, list) {
        list_del_rcu(&entry->list);
        kfree(entry->path_name);
        kfree(entry);
    }

    rcu_read_unlock();

    // Release the lock before freeing individual entries
    spin_unlock(&monitor->lock);

    // Synchronize RCU to ensure all readers have finished
    synchronize_rcu();

    // Dealloca la memoria per la password
    kfree(monitor->password);
}


// Module initialization
int init_module(void) {
    int ret;
    
    
    // Allocate monitor
    monitor = kmalloc(sizeof(struct reference_monitor), GFP_KERNEL);
    if (!monitor) {
        printk(KERN_ERR "Failed to allocate memory for monitor\n");
        return -ENOMEM;
    }
    printk("%s: Reference monitor allocated successfully %px \n", MODNAME,monitor);

    // Initialize reference monitor
    ret = reference_monitor_init();
    if (ret) {
        printk("%s: Failed to initialize reference monitor\n",MODNAME);
        return ret;
    }

    printk("%s: Reference monitor initialized successfully\n", MODNAME);
    return 0;
}

// Cleanup function
void cleanup_module(void) {
    reference_monitor_cleanup();
    kfree(monitor);
    printk("%s: Reference monitor module cleaned up\n", MODNAME);
}

EXPORT_SYMBOL(monitor);
