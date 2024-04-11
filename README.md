# SOA 23-24 Project - Reference Monitor
This is a Kernel Level Reference Monitor for File Protection, developed for Linux by using kernel modules. 

## Launch the project
Here the command to build and launch the project with all its feature: 

```
make SYMLINK=1 LINK=1 all
make install 
```

If for some reason need to restart the client is inside /ReferenceMonitor, remember to launch it as sudo.

## Project specification
This specification is related to a Linux Kernel Module (LKM) implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:
OFF, meaning that its operations are currently disabled;
ON, meaning that its operations are currently enabled;
REC-ON/REC-OFF, meaning that it can be currently reconfigured (in either ON or OFF mode).
The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.

Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:

the process TGID
the thread ID
the user-id
the effective user-id
the program path-name that is currently attempting the open
a cryptographic hash of the program file content

The the computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work.

## Black List (Monitor)
The initial aspect is the structure of the monitor.

### Structure 
To check and block various interactions with blacklisted files, the inode number of the file/directory is saved within the monitor. Specifically, the monitor maintains protected paths within a list_head structure, and each entry in this list is composed as follows:

``` 
struct protected_path{
    char* path_name; 
    ino_t inode_number;
    struct list_head list;  // Nodo per la lista collegata
};
``` 

Additionally, the monitor stores the password required for its operation, defined as follows:

``` 
struct reference_monitor {
    enum State state;  // Stato del monitor 
    struct list_head protected_paths;
    char* password;
    spinlock_t lock;
};
``` 

The spinlock is used for operations that modify the list of protected paths.

The monitor is shared among various modules of the project through the use of:

``` 
extern struct reference_monitor* monitor;
``` 

Specifically, Kretprobes, LinuxSCTFinder, and Monitor interact with the same instance of the *"struct reference_monitor"*.


### Adding Paths
When attempting to add a path:

- If it's a file, it's straightforwardly added to the blacklist.
- If it's a directory, two scenarios arise:
    1) All files and subdirectories within the directory are also blacklisted.
    2) Only the directory itself is blacklisted.

### Removing Paths
When removing paths:
1) You can either remove a specific path.
2) Alternatively, you can remove all paths stored within the monitor.

### Hard Link
Since files and directories are stored in the monitor using their inode numbers, hard links pose no issue because they share the same inode number as the original file. Therefore, creating hard links to protected files (which is not possible by default for directories) is feasible, but these hard links do not affect the original file in any way.

### Symbolic Links (Soft Link)
Blocking access to the original file of a symbolic link effectively prevents access to all symlinks pointing to that file. Since symlinks act as pointers to the original file, blocking access to the original file makes it impossible to follow the symlink to access the file's content. Consequently, any attempt to access via a blocked symlink will be unsuccessful.


## Available System Calls (LinuxSCTFinder)
This solution introduces 5 system calls to interact with the monitor.

### 134 - sys_state_update(char* state, char * password)
This system call checks if the requesting user has an effective UID (EUID) of 0, verifies the correctness of the password, and attempts to change the monitor's state. It takes two input arguments:

- *state*: the desired new state. 
- *password*: the monitor password.

### 174 - sys_configure_path(char* path ,char* password, int mod, int recursive)
This system call is more complex and can be used to add or remove paths. The path parameter specifies the path to be added or removed, and the password is required to interact with the monitor.
Regarding the other two arguments:
- *mod*: specifies the operation to be performed (0 for add, 1 for remove).
- *recursive*: used only during the "add" operation, allowing insertion of all subdirectories and files within the specified path, including the path itself.

### 182 - sys_print_paths(char* output, size_t output_size)
This system call is particularly useful for the client as it returns a list of all blacklisted paths.
- *output*: a buffer that will contain the list of paths..
- *output_size*: the maximum size of the buffer, used to prevent overflow issues.

### 183 - sys_remove_all_paths(char* password)
This system call simply receives the monitor's password and then removes all blacklisted paths. 
It can be useful when there are too many paths stored in the monitor, and removing them individually is too slow.

### 214 - sys_get_state(char* state)
This is the final implemented system call, used exclusively by the client to retrieve the current state of the monitor.
- *state*: the buffer that will contain the current state.

###  User: The Client
Users can interact directly with the monitor using a client application. The client presents a menu exposing various operations. All interactions between the user and the kernel occur through reference monitor system calls.


## Monitored Function (Kretprobes)
The objective is to block write-open operations on directories and files by monitoring and potentially blocking various functions when they interact with blacklisted paths.

### Open
The systemcalls **sys_open** and **sys_openat** relies on other low level API, see it from [here](https://elixir.bootlin.com/linux/latest/source/fs/open.c#L1423). In particular, **vfs_open** is a low level function used when open is called and is the one that is kprobed. 

For documentation: [this link](https://elixir.bootlin.com/linux/latest/source/fs/open.c#L1084). 

### Unlink
The systemcalls **sys_unlink** and **sys_unlinkat** relies on other low level API. Both of these calls internally **security_path_unlink** which checks for permission to remove the link. This API checks if the permission to remove link are granted.

Documentation is available [here](https://elixir.bootlin.com/linux/latest/source/security/security.c#L1848). 

### Rmdir
The systemcalls **sys_rmdir** relies on other low level API. Here too, there is an API that checks permissions named **security_path_rmdir**.  

Refer to the documentation [here](https://elixir.bootlin.com/linux/latest/source/security/security.c#L1832).

### Rename
The systemcalls **sys_rename** and **sys_renameat** relies on other low level API.  Similar to unlink, there is an API named security_path_rename that checks permissions. 

Documentation can be found  [here](https://elixir.bootlin.com/linux/latest/source/security/security.c#L1904).

### Mkdir
The systemcalls **sys_mkdir** and **sys_mkdirat** relies on other low level API.  Like unlink and rename, there is an API named **security_path_mkdir** for permission checking. 

Documentation is available [here](https://elixir.bootlin.com/linux/latest/source/security/security.c#L1814).

### Creation
File creation is also monitored by intercepting **security_inode_create**. 

For the documentation refer to this link: [here](https://elixir.bootlin.com/linux/latest/source/security/security.c#L1994). 

### Symlink (Not Mandatory)
The systemcalls **sys_symlink** and **sys_symlinkat** relies on other low level API. Similarly, there is an API named **security_path_symlink** for permission checking.  
Documentation can be found : [here](https://elixir.bootlin.com/linux/latest/source/security/security.c#L1866).

### Link (Not Mandatory)
The systemcalls **link** and **linkat** relies on other low level API. ASimilar to symlink, there is an API named **security_inode_link** for permission checking. 

For documentation [here](https://elixir.bootlin.com/linux/latest/source/security/security.c#L2019). 


### Pre Handler
The selection of functions to monitor was based on two key ideas:
1) Intercepting the simplest functions.
2) Intercepting functions that expose the inode of the file/directory.
The second point is crucial because most checks in the blacklist rely on filtering by inode number. Only symlink checks use the path due to the nature of the function that exposes the original file's path. Directly working with inode numbers avoid the overhead needed to obtain the absolute path of the file/directory.

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

After obtaining the inode and checking if it is present in the blacklist, all the different pre-handlers simply:
- Return 0 if the path is present (also triggers the post-handler).
- Return 1 if the path is not present (does not trigger the post-handler).

### Post Handler
The post-handlers are essentially similar in nature. They set rax to -1 or a different error code to prevent the execution of the specific operation. As mentioned earlier, the post-handler is executed only when the execution needs to be blocked (for blacklisted paths).

```
static int link_post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    the_regs->ax = -1;
    return 0;
}
```


## Log Data (singlefile-FS)

### File system
The log file is located within a custom file system that consists of only one file (the log). Customized open, read, and write operations are specific to this file system. Notably, the write function permits only append mode, ensuring that data is added at the end of the file. The file structure includes a header detailing its contents, with each row representing an attempted access to blacklisted files/directories and containing specific information such as:

- the process TGID
- the thread ID
- the user-id
- the effective user-id
- the program path-name that is currently attempting the open
- cryptographic hash of the program file content.

To enable the kernel to write to the log file, the write_iter file operation has been implemented instead of the simple write operation. As per the documentation:

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
The hash evaluation of the program file path that has accessed a blacklisted file/directory and the subsequent write operation to the log file are performed using deferred work. The write must be executed after the hash evaluation is complete, so it waits for the completion signal before proceeding with the logging.

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
The struct *work_struct* for *get_log_work* and *write_log_work* is maintained within a custom struct packed_work. This structure allows for signaling the completion of *get_log_work* to trigger the subsequent *write_log_work* operation.

## Conclusion

In this project, we have implemented a comprehensive monitoring system within the Linux kernel to enforce security policies related to file and directory access. The core components include a reference monitor module that maintains a list of protected paths and controls the system's state. Interaction with the monitor is facilitated through a set of custom system calls introduced by the LinuxSCTFinder module.

Key functionalities of the system include:

- Blacklisting Paths: Users can add, remove, or query blacklisted paths using system calls, allowing for flexible management of security policies.

- Monitoring Functions: Critical kernel functions like open, unlink, rmdir, rename, mkdir, and file creation are intercepted and monitored to enforce access restrictions based on protected paths.

- Log File System: A custom file system hosts a single log file, recording attempted accesses to blacklisted files/directories. The log entries capture detailed information such as process IDs, user IDs, and program paths for auditing purposes.

- Deferred Work Mechanism: Hash evaluation of program file paths and subsequent logging operations are handled asynchronously using deferred work. This ensures that logging occurs after the completion of hash evaluations.

Overall, the project demonstrates effective integration of kernel-level monitoring techniques to enhance system security and enforce access controls based on predefined security policies.

This conclusion summarizes the key aspects and achievements of your project, highlighting the implementation of a robust security monitoring system within the Linux kernel. Feel free to adjust or expand upon this conclusion based on additional details or insights from your report. If you have any specific points you'd like to emphasize or include, please let me know!

