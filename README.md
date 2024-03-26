# SOA 23-24 Project - Reference Monitor
This is a reference monitor implementation, developed by using Linux kernel modules. <br />

## Monitored Function
### Open
The user level systemcalls **sys_open** and **sys_openat** relies on other low level API, see it from "https://elixir.bootlin.com/linux/latest/source/fs/open.c#L1423". For instance, **do_filp_open** is one of this called by higher level open-function. By using kprobes write-open request can be intercepted, monitored and eventually blocked if the resource is black-listed. <br />
### Unlink
The user level systemcall **sys_unlink** and **sys_unlinkat** relies on other low level API. Both of them call *do_unlinkat* that calls **security_path_unlink**. This API checks if permission to remove hard link are granted, documentation on: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1848". 
### Rmdir
The user level system call **sys_rmdir** relies on other low level API. Also here there is an API that check permission, see it from "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1832"
### Rename
The user level system call **sys_rename** and **sys_renameat** relies on other low level API. Also here there is an API that check permission, for documentation: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1904"
### Mkdir
The user level system call **sys_mkdir** and **sys_mkdirat** relies on other low level API. Also here there is an API that check permission, for documentation: "https://elixir.bootlin.com/linux/6.8/source/security/security.c#L1814"