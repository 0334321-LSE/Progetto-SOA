# SOA 23-24 Project - Reference Monitor
This is a reference monitor implementation, developed by using Linux kernel modules. <br />
## Open
The user level systemcalls **sys_open** and **sys_openat** relies on other low level API, see it from "https://elixir.bootlin.com/linux/latest/source/fs/open.c#L1423". For instance, **do_filp_open** is one of this called by higher level open-function. By using kprobes write-open request can be intercepted, monitored and eventually blocked if the resource is black-listed. <br />
## Unlink
The user level systemcall **sys_unlink** and **sys_unlinkat** relies on other low level API, "https://elixir.bootlin.com/linux/latest/source/fs/namei.c#L4448". Both of them call *do_unlinkat* that calls **security_path_unlink**. This API checks if permission to remove hard link are granted. 
