# SOA 23-24 Project - Reference Monitor
This is a reference monitor implementation, developed by using Linux kernel modules. <br />
The user level systemcall **sys_openat** relies on other low level API "https://elixir.bootlin.com/linux/latest/source/fs/open.c#L1423". At low level **do_filp_open** is called by higher level open-function, so the reference monitor kprobes this function to intercept open request. <br />
