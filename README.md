# SOA 23-24 Project - Reference Monitor
This is a Kernel Level Reference Monitor for File Protection, developed for Linux by using kernel modules. 

## Black List

### Inode
To check and block the different interaction with blacklisted file the inode number of the file/directory is saved inside the monitor. Especially, the monitor mantains protected path inside a *list_head* structure and each entry of this list is composed like: 

``` 
struct protected_path{
    char* path_name; 
    ino_t inode_number;
    struct list_head list;  // Nodo per la lista collegata
};
``` 

The monitor mantains also the password to work with him, it is defined in this way: 

``` 
struct reference_monitor {
    enum State state;  // Stato del monitor 
    struct list_head protected_paths;
    char* password;
    spinlock_t lock;
};
``` 

The spinlock is used for the operation that will change the list of protected paths.



### Adding Paths
When trying to add a path , if it is a file, it is simply added to the blacklist. However, if it is a directory, there are two possibilities: 
1) All the files and subdirectories within it will be blacklisted as well.
2) Only the directory is blacklisted.

### Removing Paths
When removing there are only two possibilities:
1) Remove one specific path.
2) Remove all the paths inside the monitor.

### Hard Link
Since files and directories are stored in the monitor with their inode numbers, hard links do not pose a problem because they share the same inode number of the original file. Therefore, it is possible to create hard links to protected files (which is not possible by default for directories), but these hard links do not influence the original file in any way.

### Soft Link
When access to the original file of a symbolic link is blocked, it effectively prevents access to all the symlinks pointing to that file. Since symlinks are merely pointers to the original file, if access to the original file is blocked, following the symlink to access the file content becomes impossible. Consequently, any attempt to access via a blocked symlink will be disrupted.


## Available System Calls
This solution introduces 5 system call to work with the monitor.

### 134 - sys_state_update(char* state, char * password)
This system call checks if the user that requested has EUID = 0, verify that password is the right one and then try to change the monitor state. 
It has two input arguments:
- *state* the new wanted state 
- *password* the monitor password.

### 174 - sys_configure_path(char* path ,char* password, int mod, int recursive)
This system call is a bit more complex. It can be used to add and also to remove path. 
The *path* is the one that want to be added/removed and *password* is needed to work with monitor. 
About the other two arguments: 
- *mod* specify wich operation must be done: 0 for add 1 for remove.
- *recursive* is used only during the add modality. It permits to insert all the subdir and file in a specific path, included the path at hand. 

### 182 - sys_print_paths(char* output, size_t output_size)
This system call is helpful espacially for the client. It returns all the blacklisted paths.
- *output* is the buffer that will contain the list of paths.
- *output_size* is the max size of the buffer, used to avoid some overflow.

### 183 - sys_remove_all_paths(char* password)
This system call simply get the password of the monitor and then remove all the black listed path. 
It may be useful when to many paths are inside the monitor and removing them one by one is to slow.

### 214 - sys_get_state(char* state)
This is the last system call implemented. It is used only by the client to get the current state of the monitor
- *state* is the buffer that will contain the current state.


###  User: The Client
The user can interact directly with the monitor by using a client. This client show a menu where the possible operations are exposed. 
All the interaction between user and kernel happen by using reference monitor systemcalls.


## Monitored Function (Kretprobes)
### Open
The systemcalls **sys_open** and **sys_openat** relies on other low level API, see it from "https://elixir.bootlin.com/linux/latest/source/fs/open.c#L1423". In particular, **vfs_open** is a low level function used when open is called and is the one that is kprobed. 
For the documentation: "https://elixir.bootlin.com/linux/latest/source/fs/open.c#L1084". 

### Unlink
The systemcalls **sys_unlink** and **sys_unlinkat** relies on other low level API. Both of them call inside **security_path_unlink**. This API checks if the permission to remove link are granted, documentation on: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1848". 

### Rmdir
The systemcalls **sys_rmdir** relies on other low level API. Also here there is an API that check permission **security_path_rmdir**, see it from "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1832"

### Rename
The systemcalls **sys_rename** and **sys_renameat** relies on other low level API. Also here there is an API that check permission **security_path_rename**, for the documentation: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1904"

### Mkdir
The systemcalls **sys_mkdir** and **sys_mkdirat** relies on other low level API. Also here there is an API that check permission **security_path_mkdir**, for the documentation: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1814"

### Creation
Also file creation is monitored, in this case by intercepting  **security_inode_create**. 
For the documentation: "https://elixir.bootlin.com/linux/latest/source/security/security.c#L1994". 

### Symlink (Not Mandatory)
The user level system call **sys_symlink** and **sys_symlinkat** relies on other low level API. Also here there is an API that check permission **security_path_symlink**, for the documentation: "https://elixir.bootlin.com/linux/latest/source/security/security.c#L1866".

### Link (Not Mandatory)
The user level system call **link** and **linkat** relies on other low level API. Also here there is an API that check permission **security_inode_link**, for the documentation: "https://elixir.bootlin.com/linux/latest/source/security/security.c#L2019". 


### Pre Handler
The choice of the functio to monitor was made by following two key ideas:
1) Try to intercept the most simple function.
2) Intercept a function that exposes the inode of the file/dir.
In particular the second point is basic beacause almost all the check in the black list happen by inode, only often in some particular cases happen by explicit path due to the overhead needed to get the absolute path.

```
int inode_in_protected_paths(long unsigned int inode_number){
    struct protected_path *entry; 
    // Iterate on the list, *_safe is not required is needed only for removes
    list_for_each_entry(entry, &monitor->protected_paths, list){
        // strncmp more secure in respect of strcmp, prevents buffer overflow
        if (entry->inode_number == inode_number) {
            // Il percorso è presente nella lista dei percorsi protetti
            return 1;       
        }
    }

    // Il percorso non è presente nella lista dei percorsi protetti
    return 0;
}
```

After obtain the inode and check if is present in the blacklist, all the different pre handler simply:
- If the path is present then return 0 (*run also the post handler*) 
- If the path isn't present then return 1 (*doesn't run the post handler*)

### Post Handler
The post handler are essentially all similar togheter. They put in rax the -1 value or a different error code that prevents the execution of the specific operation. As specified before the post handler is runned only when the execution must be blocked (*blacklisted path*)
## Log Data

### Singlefs
The log file is located into a custom file system that contains only one file (the log). The open, read and write operation are custom and specific for that file system. In particular the write function allows only the append mode, so the data are written at the end of the file. The file is composed by an header that shows the contents and each row represent an attempted access to black listed file/dir with specific information like: 

- the process TGID
- the thread ID
- the user-id
- the effective user-id
- the program path-name that is currently attempting the open
- cryptographic hash of the program file content.

In particular, to able the kernel to write inside the log file is been implemented write_iter file operation and not implemented the simple write, as documentation says: 

``` 
/* caller is responsible for file_start_write/file_end_write */
ssize_t __kernel_write_iter(struct file *file, struct iov_iter *from, loff_t *pos)
{
    ...
	if (unlikely(!file->f_op->write_iter || file->f_op->write))
		return warn_unsupported(file, "write");
    ...
	return ret;
}
``` 


### Defered Work
The hash evaluation of the file program path that has accessed a blacklisted file/dir and the write on the log file is done in defered work. The write must be executed after the hash evalutation, so it waits the completition and after that is issued. 

``` 
struct packed_work{
    struct log_entry * the_entry;
    struct work_struct get_log_work;
    struct work_struct write_log_work;
    struct completion get_log_completion;
};

static void get_log_work_function(struct work_struct *work) {
    struct packed_work *p_work = container_of(work, struct packed_work, get_log_work);
    struct log_entry* entry = p_work->the_entry;

    get_path_and_hash(entry);

    // Signal completion of get_log_work
    complete(&p_work->get_log_completion);
    
}

static void write_log_work_function(struct work_struct *work) {
    struct packed_work *p_work = container_of(work, struct packed_work, write_log_work);
    struct log_entry* entry = p_work->the_entry;
    
    // Wait until get_log_work is completed
    wait_for_completion(&p_work->get_log_completion);

    // Perform the logging operation
    write_log_entry(entry);
}
``` 
The struct *work_struct* for get_log and write_log is manteined inside a custom struct **packed_work**, this permits to notify the completition to the write_log.




