# SOA 23-24 Project - Reference Monitor
This is a reference monitor implementation, developed by using Linux kernel modules. <br />

## Black listed path
### Adding Path
When a path is added, if it is a file, it is simply added to the blacklist. However, if it is a directory, all the files and subdirectories within it will be blacklisted as well
### Hard Link
Since files and directories are stored in the monitor with their inode numbers, hard links do not pose a problem because they share the same inode number of the original file. Therefore, it is possible to create hard links to protected files (which is not possible by default for directories), but these hard links do not influence the original file in any way.
### Soft Link
When access to the original file of a symbolic link is blocked, it effectively prevents access to all the symlinks pointing to that file. Since symlinks are merely pointers to the original file, if access to the original file is blocked, following the symlink to access the file content becomes impossible. Consequently, any attempt to access via a blocked symlink will be disrupted.

## Monitored Function
### Open
The user level systemcalls **sys_open** and **sys_openat** relies on other low level API, see it from "https://elixir.bootlin.com/linux/latest/source/fs/open.c#L1423". For instance, **vfs_open** is a low level function used when open is called. By using kprobes write-open request can be intercepted, monitored and eventually blocked if the resource is black-listed. <br />
### Unlink
The user level systemcall **sys_unlink** and **sys_unlinkat** relies on other low level API. Both of them call *do_unlinkat* that calls **security_path_unlink**. This API checks if permission to remove hard link are granted, documentation on: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1848". 
### Rmdir
The user level system call **sys_rmdir** relies on other low level API. Also here there is an API that check permission, see it from "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1832"
### Rename
The user level system call **sys_rename** and **sys_renameat** relies on other low level API. Also here there is an API that check permission, for documentation: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1904"
### Mkdir
The user level system call **sys_mkdir** and **sys_mkdirat** relies on other low level API. Also here there is an API that check permission, for documentation: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1814"
### Creation
Also file creation is monitored by intercepting **security_inode_create** "https://elixir.bootlin.com/linux/latest/source/security/security.c#L1994". When there is an attempt to create file inside a blacklisted dir it will be blocked.
### Symlink (Not Mandatory)
The user level system call **sys_symlink** and **sys_symlinkat** relies on other low level API. Also here there is an API that check permission, for documentation: "https://elixir.bootlin.com/linux/latest/source/security/security.c#L1866". This API can be blocked to rise the security level.

## Some Problems

