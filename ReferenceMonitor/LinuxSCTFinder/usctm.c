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
* @file usctm.c 
* @brief This is the main source for the Linux Kernel Module which implements
* 	 the runtime discovery of the syscall table position and of free entries (those 
* 	 pointing to sys_ni_syscall) 
*
* @author Francesco Quaglia
*
* @date November 22, 2020
*/

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include "./include/vtpmo.h"
#include "../reference_monitor.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Quaglia <framcesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("USCTM");



#define MODNAME "USCTM"

extern int sys_vtpmo(unsigned long vaddr);

#define ADDRESS_MASK 0xfffffffffffff000//to migrate

#define START 			0xffffffff00000000ULL		// use this as starting address --> this is a biased search since does not start from 0xffff000000000000
#define MAX_ADDR		0xfffffffffff00000ULL
#define FIRST_NI_SYSCALL	134
#define SECOND_NI_SYSCALL	174
#define THIRD_NI_SYSCALL	182 
#define FOURTH_NI_SYSCALL	183
#define FIFTH_NI_SYSCALL	214	
#define SIXTH_NI_SYSCALL	215	
#define SEVENTH_NI_SYSCALL	236	

#define ENTRIES_TO_EXPLORE 256

unsigned long *hacked_ni_syscall=NULL;
unsigned long **hacked_syscall_tbl=NULL;

unsigned long sys_call_table_address = 0x0;
module_param(sys_call_table_address, ulong, 0660);

unsigned long sys_ni_syscall_address = 0x0;
module_param(sys_ni_syscall_address, ulong, 0660);

int good_area(unsigned long * addr){

	int i;
	
	for(i=1;i<FIRST_NI_SYSCALL;i++){
		if(addr[i] == addr[FIRST_NI_SYSCALL]) goto bad_area;
	}	

	return 1;

bad_area:

	return 0;

}



/* This routine checks if the page contains the begin of the syscall_table.  */
int validate_page(unsigned long *addr){
	int i = 0;
	unsigned long page 	= (unsigned long) addr;
	unsigned long new_page 	= (unsigned long) addr;
	for(; i < PAGE_SIZE; i+=sizeof(void*)){		
		new_page = page+i+SEVENTH_NI_SYSCALL*sizeof(void*);
			
		// If the table occupies 2 pages check if the second one is materialized in a frame
		if( 
			( (page+PAGE_SIZE) == (new_page & ADDRESS_MASK) )
			&& sys_vtpmo(new_page) == NO_MAP
		) 
			break;
		// go for patter matching
		addr = (unsigned long*) (page+i);
		if(
			   ( (addr[FIRST_NI_SYSCALL] & 0x3  ) == 0 )		
			   && (addr[FIRST_NI_SYSCALL] != 0x0 )			// not points to 0x0	
			   && (addr[FIRST_NI_SYSCALL] > 0xffffffff00000000 )	// not points to a locatio lower than 0xffffffff00000000	
	//&& ( (addr[FIRST_NI_SYSCALL] & START) == START ) 	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SECOND_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[THIRD_NI_SYSCALL]	 )	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[FOURTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[FIFTH_NI_SYSCALL] )	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SIXTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SEVENTH_NI_SYSCALL] )	
			&&   (good_area(addr))
		){
			hacked_ni_syscall = (void*)(addr[FIRST_NI_SYSCALL]);				// save ni_syscall
			sys_ni_syscall_address = (unsigned long)hacked_ni_syscall;
			hacked_syscall_tbl = (void*)(addr);				// save syscall_table address
			sys_call_table_address = (unsigned long) hacked_syscall_tbl;
			return 1;
		}
	}
	return 0;
}

/* This routines looks for the syscall table.  */
void syscall_table_finder(void){
	unsigned long k; // current page
	unsigned long candidate; // current page

	for(k=START; k < MAX_ADDR; k+=4096){	
		candidate = k;
		if(
			(sys_vtpmo(candidate) != NO_MAP) 	
		){
			// check if candidate maintains the syscall_table
			if(validate_page( (unsigned long *)(candidate)) ){
				printk("%s: syscall table found at %px\n",MODNAME,(void*)(hacked_syscall_tbl));
				printk("%s: sys_ni_syscall found at %px\n",MODNAME,(void*)(hacked_ni_syscall));
				break;
			}
		}
	}
	
}


#define MAX_FREE 15
int free_entries[MAX_FREE];
module_param_array(free_entries,int,NULL,0660);//default array size already known - here we expose what entries are free

// INSTALL FIRST SYSCALL

#define SYS_CALL_INSTALL

#ifdef SYS_CALL_INSTALL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _state_update, char*, state, char*, password){
#else
asmlinkage long sys_state_update(char* state ,char* password){
#endif
		// States for cute printing
		enum State old_state;
		enum State new_state;
		
		// Vector of states for cute printing
		const char* states[] = {"OFF", "REC_OFF", "ON", "REC_ON"};
		char* kernel_password;
		// Check monitor
		if ( !monitor ){
			printk("%s: Monitor isn't allocated, install rm_module before using this one.\n",MODNAME);
			return-EINVAL; // Monitor doesn't exists
		}
		
		old_state = monitor->state;

		// kmalloc password into kernel space, PASW_MAX_LENGTH is the maximium size of the password in the kernel.
		kernel_password = kmalloc(PASW_MAX_LENGTH, GFP_KERNEL);
		if (!kernel_password)
			return -ENOMEM; 
			
		// Copy from user space the password.
		if (copy_from_user(kernel_password, password, PASW_MAX_LENGTH)) {
			kfree(kernel_password);
			return -EFAULT;
		}

		// Check password
		if (strncmp(kernel_password, monitor->password, strlen(monitor->password)) != 0) {
			printk("%s: Password isn't valid.\n",MODNAME);
			return -EINVAL;  // Not valid password 
	}
		// Update monitor state
		if (strncmp(state, "ON",strlen("ON")) == 0) {
			monitor->state = ON;
		} else if (strncmp(state, "OFF",strlen("OFF")) == 0) {
			monitor->state = OFF;
		} else if (strncmp(state, "REC-ON",strlen("REC-ON")) == 0) {
			monitor->state = REC_ON;
		} else if (strncmp(state, "REC-OFF",strlen("REC-OFF")) == 0) {
			monitor->state = REC_OFF;
		} else {
			return -EINVAL;  // Stato non valido
		}

		new_state = monitor->state;
		/*spin_unlock(&monitor->lock);
		printk("%s: UNLOCK \n",MODNAME);*/

        printk("%s: State changed from %s to %s correctly by thread: %d\n",MODNAME,states[old_state],states[new_state],current->pid);

		return 0;  // Successo
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_state_update = (unsigned long) __x64_sys_state_update;	
#else
#endif

// SECOND SYSCALL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(3, _configure_path, char*, path, char*, password, int, mod){
#else
asmlinkage long sys_configure_path(char* path ,char* password, int mod){
#endif
	
	// Vector of states for cute printing
	const char* states[] = {"OFF", "REC_OFF", "ON", "REC_ON"};
	char *kernel_password;
	char *kernel_path;
	struct protected_path *entry, *tmp;

	// Check monitor
	if ( !monitor ){
		printk("%s: Monitor isn't allocated, install rm_module before using this one.\n",MODNAME);
		return-EINVAL; // Monitor doesn't exists
	}

	// Check monitor state  (it can be reconfigured only in REC-OFF or REC-ON)
	if ( monitor->state == 0 || monitor->state == 2){
		printk("%s: Can't re-configure monitor in %s state.\n", MODNAME, states[monitor->state]);
		return -EPERM; // State is wrong
	}

	// kmalloc password into kernel space, PASW_MAX_LENGTH is the maximium size of the password in the kernel.
	kernel_password = kmalloc(PASW_MAX_LENGTH, GFP_KERNEL);
	if (!kernel_password)
		return -ENOMEM; 

	// Copy from user space the password.
	if (copy_from_user(kernel_password, password, PASW_MAX_LENGTH)) {
		kfree(kernel_password);
		return -EFAULT;
	}

	// Check password
	if (strncmp(kernel_password, monitor->password, strlen(monitor->password)) != 0) {
		printk("%s: Password isn't valid.\n",MODNAME);
		return -EINVAL;  // Not valid password 
	}
	
	// kmalloc path into kernel space, PATH_MAX is the maximium size of a path in the kernel.
	kernel_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kernel_path)
		return -ENOMEM; 

	// Copy from user space the path.
	if (copy_from_user(kernel_path, path, PATH_MAX)) {
		kfree(kernel_path);
		return -EFAULT;
	}

	switch (mod)
	{
	case 0 /* ADD */:

		// Check if path is already present
		if(file_in_protected_paths(kernel_path)){
			printk("%s: Path %s already exists \n", MODNAME, kernel_path);
			return -EINVAL;
		}

		if(is_directory(kernel_path))
			//will iterate over the directory and its subdir:
			add_dir(MODNAME,kernel_path);
			
		else
			add_file(MODNAME,kernel_path);
		
		break;
		
	case 1 /* REMOVE*/:

		
		spin_lock(&monitor->lock);

		// find and remove the path 
		list_for_each_entry_safe(entry, tmp, &monitor->protected_paths, list) {
			if (strncmp(entry->path_name, kernel_path, strlen(entry->path_name)) == 0) {
				list_del(&entry->list);
				kfree(entry);
				spin_unlock(&monitor->lock);
			
				printk("%s: Path %s removed successfully by %d\n",MODNAME, kernel_path,current->pid);
				kfree(kernel_path);
				return 0;
			}
		}
		spin_unlock(&monitor->lock);

		// Return error if path doesn't exist
		printk("%s: Path %s doesn't exists %d\n",MODNAME, kernel_path,current->pid);
		kfree(kernel_path);
		return -ENOENT; // Path not find
    
	default:
		kfree(kernel_path);
		printk("%s: Modality %d is not supported by this systemcall \n",MODNAME, mod);
		return -EINVAL;
	}	

	return 0; // Successo
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_configure_path = (unsigned long) __x64_sys_configure_path;	
#else
#endif

// THIRD SYSCALL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _print_paths,  char*, password){
#else
asmlinkage long sys_print_paths(char* password){
#endif
	char * kernel_password;
	struct protected_path *entry;
	int i;
	// Check monitor
	if ( !monitor ){
		printk("%s: Monitor isn't allocated, install rm_module before using this one.\n",MODNAME);
		return-EINVAL; // Monitor doesn't exists
	}

	// kmalloc password into kernel space, PASW_MAX_LENGTH is the maximium size of the password in the kernel.
	kernel_password = kmalloc(PASW_MAX_LENGTH, GFP_KERNEL);
	if (!kernel_password)
		return -ENOMEM; 
		
	// Copy from user space the password.
	if (copy_from_user(kernel_password, password, PASW_MAX_LENGTH)) {
		kfree(kernel_password);
		return -EFAULT;
	}

	// Check password
	if (strncmp(kernel_password, monitor->password, strlen(monitor->password)) != 0) {
		printk("%s: Password isn't valid.\n",MODNAME);
		return -EINVAL;  // Not valid password 
	}	

	spin_lock(&monitor->lock);
	i=1;
	// Print all the entry
	list_for_each_entry(entry, &monitor->protected_paths, list) {

		printk("%s: Protected path-%d  %s \n",MODNAME, i,entry->path_name);
		i++;
	}
	spin_unlock(&monitor->lock);

	return 0;

} 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_print_paths = (unsigned long) __x64_sys_print_paths;	
#else
#endif
unsigned long cr0;

static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void
protect_memory(void)
{
    write_cr0_forced(cr0);
}

static inline void
unprotect_memory(void)
{
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}


#else
#endif





int init_module(void) {
	
	int i,j;
		
        printk("%s: initializing\n",MODNAME);
	
	syscall_table_finder();

	if(!hacked_syscall_tbl){
		printk("%s: failed to find the sys_call_table\n",MODNAME);
		return -1;
	}

	j=0;
	for(i=0;i<ENTRIES_TO_EXPLORE;i++)
		if(hacked_syscall_tbl[i] == hacked_ni_syscall){
			printk("%s: found sys_ni_syscall entry at syscall_table[%d]\n",MODNAME,i);	
			free_entries[j++] = i;
			if(j>=MAX_FREE) break;
		}

#ifdef SYS_CALL_INSTALL
	cr0 = read_cr0();
	unprotect_memory();
	hacked_syscall_tbl[FIRST_NI_SYSCALL] = (unsigned long*)sys_state_update;
	hacked_syscall_tbl[SECOND_NI_SYSCALL] = (unsigned long*)sys_configure_path;
	hacked_syscall_tbl[THIRD_NI_SYSCALL] = (unsigned long*)sys_print_paths;

	protect_memory();
	printk("%s: Added state_update on the sys_call_table at displacement %d\n",MODNAME,FIRST_NI_SYSCALL);
	printk("%s: Added configure_path on the sys_call_table at displacement %d\n",MODNAME,SECOND_NI_SYSCALL);	
	printk("%s: Added print_paths on the sys_call_table at displacement %d\n",MODNAME,THIRD_NI_SYSCALL);	

	printk("%s: module correctly mounted\n",MODNAME);
#else
#endif

	return 0;

}

void cleanup_module(void) {
                
#ifdef SYS_CALL_INSTALL
	cr0 = read_cr0();
	unprotect_memory();
	hacked_syscall_tbl[FIRST_NI_SYSCALL] = (unsigned long*)hacked_ni_syscall;
	hacked_syscall_tbl[SECOND_NI_SYSCALL] = (unsigned long*)hacked_ni_syscall;
	hacked_syscall_tbl[THIRD_NI_SYSCALL] = (unsigned long*)hacked_ni_syscall;

	protect_memory();
#else
#endif
	printk("%s: shutting down\n",MODNAME);
        
}
