#include "reference_monitor.h"

static bool add_entry_actor(struct dir_context *ctx, const char *name, int type, loff_t offset, u64 ino, unsigned d_type);

/* inline int file_in_protected_paths(const char* filename){
    struct protected_path *entry;
    // Acquisisci la spinlock per accedere alla lista dei percorsi protetti
    //spin_lock(&monitor->lock);

    // Iterate on the list, *_safe is not required is needed only for removes
    list_for_each_entry(entry, &monitor->protected_paths, list){
        // strncmp more secure in respect of strcmp, prevents buffer overflow
        if (strncmp(entry->path_name, filename, strlen(entry->path_name)) == 0) {
            // Il percorso è presente nella lista dei percorsi protetti
            //spin_unlock(&monitor->lock);

            return 1;       
        }
    }

    // Rilascia la spinlock
    //spin_unlock(&monitor->lock);

    // Il percorso non è presente nella lista dei percorsi protetti
    return 0;
} */


inline int is_directory(const char *path) {
    struct path p;
    int ret = 0;

    // Prende la dentry del percorso
    if (kern_path(path, 0, &p) == 0) {
        // Verifica se è una directory
        if (S_ISDIR(p.dentry->d_inode->i_mode)) {
            ret = 1; // Sì, è una directory
        }
        path_put(&p);
    }

    return ret; // No, non è una directory
}

inline int add_file(char* modname, const char* path){
    struct protected_path *entry;

 		// kmalloc one protected path
		entry = kmalloc(sizeof(struct protected_path), GFP_KERNEL);
		if (!entry) {
			printk("%s: Entry can't be allocated \n",modname);
			kfree(path);
            return -ENOMEM; 
		}

		entry->path_name = kstrdup(path, GFP_KERNEL);
		if (!entry->path_name){
			printk("%s: Entry pathname can't be allocated \n",modname);
			kfree(path);
			kfree(entry);
            return -ENOMEM;
		}

		entry->inode_number = get_inode_from_path(path);
		if (entry->inode_number == 0){
			printk("%s: Entry inode number can't be found \n",modname);
			kfree(path);
			kfree(entry);
            return -ENOENT; 
		}

		// Acquire lock to work with the list
		spin_lock(&monitor->lock);

		list_add(&entry->list, &monitor->protected_paths);

		spin_unlock(&monitor->lock);

		printk("%s: Path %s with inode: %ld added successfully by %d\n",modname, path, entry->inode_number ,current->pid);
    return 0;
}

inline int add_dir(char* modname, const char* path){

    struct file *dir;
    struct my_dir_context context;
    char * dir_path = kstrdup(path, GFP_KERNEL);
    if (!dir_path) {
        printk(KERN_ERR "Failed to allocate memory for destination string\n");
        kfree(dir_path);
        return 0;
    }

    // Assegnated in this way to avoid stupid warning 
    context.dir_ctx.actor = &add_entry_actor;
    context.dir_path = dir_path;
    context.modname = modname;

    // printk("%s: Path %s is a dir \n", modname, path);
    // Open
    dir = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(dir)) {
        pr_err("%s: Errore during directory opening %s\n", modname ,path);
        return -EFAULT;
    }

    // Iterate
    iterate_dir(dir, &context.dir_ctx);

    // Close
    filp_close(dir, NULL);

    // Then add the directory
    add_file(modname,path);
    return 0;
}

static bool add_entry_actor(struct dir_context *ctx, const char *name, int type, loff_t offset, u64 ino, unsigned d_type) {
	char *full_path;
    char *file_name;
    char last_char;
	// retrieve base dir path from struct custom_dir_context 
	struct my_dir_context *my_ctx = container_of(ctx, struct my_dir_context, dir_ctx);

    char *modname = kstrdup(my_ctx->modname, GFP_KERNEL);
    if (!modname) {
        printk(KERN_ERR "Failed to allocate memory for destination string\n");
        kfree(modname);
        return false;
    }

	// Build full path by using parent directory path passed to iterate_dir and current filename:
    // 1 Copy the path of parent dir
        full_path = kmalloc(strlen(my_ctx->dir_path)+1, GFP_KERNEL);
        if (!full_path){
            printk("%s: Can't alloc memory for full path \n",modname);
            return -ENOMEM;
        }
        strcpy(full_path, my_ctx->dir_path);
        
    // 2 Add the file/directory name to this path
        file_name = kmalloc(strlen(name)+1, GFP_KERNEL);
        if (!file_name) {
                printk("%s: kmalloc allocation error (process_dir_entry)\n", modname);
                kfree(full_path);
                return false;
        }

        strncpy(file_name, name, strlen(name));
        file_name[strlen(name)] = '\0'; 
        //printk("%s: Adding filename: %s \n",modname,file_name);


	/* exclude current and parent directories */
    if (strcmp(file_name, ".") && strcmp(file_name, "..")) {
        /* reconstruct file/subdirectory path 
        last_char = (full_path[strlen(full_path-1)]);
        printk("%s: Last char: %c",modname,last_char);
        // add the "/"" to the end if the parent dir path doesn't include it
        if( last_char != '/')*/
        strcat(full_path, "/");

        // then add the dir/file name
        strcat(full_path, file_name);

        //printk("%s: Adding full path: %s \n",modname,full_path);
        if (d_type == DT_DIR) {         /* subdirectory */
    
            struct file *subdir = filp_open(full_path, O_RDONLY, 0);
            
            if (IS_ERR(subdir)) {
                    printk("%s: error during file opening %s\n", modname, full_path);
                    kfree (full_path);
                    kfree (file_name);
                    return PTR_ERR(subdir);
            }

            add_dir(modname, full_path);
                    
        } else {        /* file */

            add_file(modname, full_path);

        }
    }

    kfree (file_name);
    kfree(full_path);
    return true;
}

inline int file_in_protected_paths(const char* filename){
    struct protected_path *entry;
    ino_t inode_number;
   
    inode_number = get_inode_from_path(filename);
    if (inode_number == 0)
        //not valid path
        return 0;

    // Iterate on the list, *_safe is not required is needed only for removes
    list_for_each_entry(entry, &monitor->protected_paths, list){
        if (entry->inode_number == inode_number) {
            return 1;       
        }
    }

    // Il percorso non è presente nella lista dei percorsi protetti
    return 0;
}



inline ino_t get_inode_from_path(const char* percorso){
    struct path path;
    struct dentry *dentry;
    ino_t inode_number;
    int ret;
    char * pathname;

    // Ottieni il percorso del file
    pathname = kstrdup(percorso, GFP_KERNEL);
    if (!pathname) {
        printk(KERN_ERR "Failed to allocate memory for destination string\n");
        kfree(pathname);
        return 0;
    }

    ret = kern_path(pathname, LOOKUP_FOLLOW, &path); 
    if (ret == -ENOENT) {
        ret = kern_path(strcat(pathname, "~"), LOOKUP_FOLLOW, &path);
        if (ret){
            printk("Can't find absolute path");
            kfree(pathname);
            return 0;
        }    
    }

    dentry = path.dentry;

    // Ottieni l'inode del file
    inode_number = dentry->d_inode->i_ino;

    path_put(&path);
    kfree(pathname);
    return inode_number;
}

inline int inode_in_protected_paths(long unsigned int inode_number){
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

inline int parent_is_blacklisted(const struct dentry* dentry){
    struct dentry * parent_dentry = dentry->d_parent;
    printk("Parent path of %s ino %ld is : %s ",dentry->d_name.name,dentry->d_inode->i_ino, parent_dentry->d_name.name);
    if (parent_dentry) {
        struct inode *parent_inode = parent_dentry->d_inode;;
        printk("Parent inode: %ld ",parent_inode->i_ino);

        if (inode_in_protected_paths(parent_inode->i_ino)) {
            return 1;
        } 
        dput(parent_dentry);
        return 0;
    }else{
      printk("Can't find node parent");
      return 0; 
    }
}
