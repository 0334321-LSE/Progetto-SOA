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
#include "reference_monitor.h"  

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Saverio Esposito <lucasavespo17@gmail.com>");
MODULE_DESCRIPTION("Kernel module that implements reference monitor");

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


struct reference_monitor* monitor;

// Implementazione dell'operazione di inizializzazione del monitor
int reference_monitor_init(char* password) {
    INIT_LIST_HEAD(&monitor->protected_paths);  // Inizializza la lista dei percorsi protetti
    spin_lock_init(&monitor->lock);  // Inizializza lo spinlock

    // Imposta lo stato iniziale del monitor (OFF)
    monitor->state = OFF;

    // Inizializza il campo della password 
    monitor->password = kstrdup(password, GFP_KERNEL);
    if (!monitor->password)
        return -ENOMEM;  // Errore di memoria

    return 0;  // Successo
}

// Implementazione dell'operazione di release del monitor
void reference_monitor_cleanup(void) {
    struct protected_path *entry, *tmp;

    // Libera tutti i percorsi protetti nella lista
    spin_lock(&monitor->lock);

    list_for_each_entry_safe(entry, tmp, &monitor->protected_paths, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    
    // Dealloca la memoria per la password
    kfree(monitor->password);
    spin_unlock(&monitor->lock);

}

// Module initialization
int init_module(void) {
    int ret;
    char* pasw = "abc";
    
    // Allocate monitor
    monitor = kmalloc(sizeof(struct reference_monitor), GFP_KERNEL);
    if (!monitor) {
        printk(KERN_ERR "Failed to allocate memory for monitor\n");
        return -ENOMEM;
    }
    printk("%s: Reference monitor allocated successfully %px \n", MODNAME,monitor);

    // Initialize reference monitor
    ret = reference_monitor_init(pasw);
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
