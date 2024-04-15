#include "reference_monitor.h"


#if  LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
/**
 * @brief Iterate over a directory. For each file/dir inside, 
 * composes the full path and add to the monitor.
 * @see int add_file(char* modname, const char* path) Handler to add file
 * @see int add_dir(char* modname, const char* path) Handler to add dir
 * 
 * @param ctx 
 * @param name 
 * @param type 
 * @param offset 
 * @param ino 
 * @param d_type 
 * @return true 
 * @return false 
 */
static bool add_entry_actor(struct dir_context *ctx, const char *name, int type, loff_t offset, u64 ino, unsigned d_type);
#else
/**
 * @brief Iterate over a directory. For each file/dir inside, 
 * composes the full path and add to the monitor.
 * @see int add_file(char* modname, const char* path) Handler to add file
 * @see int add_dir(char* modname, const char* path) Handler to add dir
 * 
 * @param ctx 
 * @param name 
 * @param type 
 * @param offset 
 * @param ino 
 * @param d_type 
 * @return int 
 */
static int add_entry_actor(struct dir_context *ctx, const char *name, int type, loff_t offset, u64 ino, unsigned d_type);
#endif

char *get_path_from_dentry(struct dentry *dentry);
int calculate_sha256(const char *input, size_t input_len, char *output);

// Just for debugging 
void print_log_entry(struct log_entry *entry);


/**
 * @brief Get file path and check if the file is a directory
 * 
 * @param path 
 * @return int 
 */
int is_directory(const char *path) {
    struct path p;
    int ret = 0;

    // Get path dentry
    if (kern_path(path, 0, &p) == 0) {
        // Verify if is a directory
        if (S_ISDIR(p.dentry->d_inode->i_mode)) {
            ret = 1; 
        }
        path_put(&p);
    }

    return ret; // No, non è una directory
}

/**
 * @brief Takes a path and add it to the monitor 
 * 
 * @param modname Prints better
 * @param path The path to add inside the monitor 
 * @return int 
 */
int add_file(char* modname, const char* path){
    struct protected_path *entry;
    int ret = 0;

    // kmalloc protected path
    entry = kmalloc(sizeof(struct protected_path), GFP_KERNEL);
    if (!entry) {
        printk("%s: Entry can't be allocated \n",modname);
        ret = -ENOMEM; 
        goto end;
    }

    entry->path_name = kstrdup(path, GFP_KERNEL);
    if (!entry->path_name){
        printk("%s: Entry pathname can't be allocated \n",modname);
        ret = -ENOMEM; 
        kfree(entry);
        goto end;
    }

    entry->inode_number = get_inode_from_path(path);
    if (entry->inode_number == 0){
        printk("%s: Entry inode number can't be found for %s \n",modname, path);
        ret = -ENOENT;
        kfree(entry);
        goto end;
    }

    // Acquire lock to work with the list
    spin_lock(&monitor->lock);

    list_add(&entry->list, &monitor->protected_paths);

    spin_unlock(&monitor->lock);

    //printk("%s: Path %s with inode: %ld added successfully by %d\n",modname, path, entry->inode_number ,current->pid);
    
end:
    return ret;
}

/**
 * @brief Takes a path of a dir, setup the context 
 * and iterate over the dir to add all the files and subdirs inside it.
 * 
 * @param modname 
 * @param path 
 * @return int 
 */
int add_dir(char* modname, const char* path){

    struct file *dir;
    struct my_dir_context context;
    int ret = 0;
    context.dir_ctx.actor = &add_entry_actor;
    // Assegnated in this way to avoid stupid warning 

    context.dir_path = kstrdup(path, GFP_KERNEL);
    
    if(!context.dir_path){
        printk("%s Error during context creation ",modname);
        return -ENOMEM;
    }
    context.modname = kstrdup(modname, GFP_KERNEL);;
    if(!context.modname){
        printk("%s Error during context creation ",modname);
        return -ENOMEM;
    }

    // printk("%s: Path %s is a dir \n", modname, dir_path);

    // Open
    dir = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(dir)) {
        pr_err("%s: Error during directory opening %s\n", modname ,path);
        return -EFAULT;
    }

    // Iterate
    iterate_dir(dir, &context.dir_ctx);

    // Close
    filp_close(dir, NULL);

    // Then add the directory
    ret = add_file(modname,path);

    return ret;
}

#if  LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
// The definition of the function change (static bool / static int)
static bool add_entry_actor(struct dir_context *ctx, const char *name, int type, loff_t offset, u64 ino, unsigned d_type) {
	char *full_path;
    char *file_name;
    char last_char;
	// retrieve base dir path from struct custom_dir_context 
	struct my_dir_context *my_ctx = container_of(ctx, struct my_dir_context, dir_ctx);
    bool ret = true;

    char *modname = kstrdup(my_ctx->modname, GFP_KERNEL);
    if (!modname) {
        printk(KERN_ERR "Failed to allocate memory for destination string\n");
        return false;
    }

	// Build full path by using parent directory path passed to iterate_dir and current filename:
    // 1 Copy the path of parent dir
        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!full_path){
            printk("%s: Can't alloc memory for full path \n",modname);
            ret = -ENOMEM;
            goto free_modname;
           
        }

        strcpy(full_path, my_ctx->dir_path);
        
    // 2 Add the file/directory name to this path
        file_name = kstrdup(name, GFP_KERNEL);
        if (!file_name) {
            printk("%s: kmalloc allocation error (process_dir_entry)\n", modname);
            ret = -ENOMEM;
            goto free_fullpath;
        }

	/* exclude current and parent directories */
    if (strcmp(file_name, ".") && strcmp(file_name, "..")) {
        /* reconstruct file/subdirectory path  */
        last_char = (full_path[strlen(full_path)-1]);
        
        //printk("%s: Last char: %c",modname,last_char);
        
        // add the "/"" to the end if the parent dir path doesn't include it
        if( last_char != '/'){
            if(strlcat(full_path, "/", PATH_MAX) >= PATH_MAX){
                printk("%s Failed to append slash to directory path\n",modname);
                ret = false;
                goto free_filename;
            }
        }
        // then add the dir/file name
        if(strlcat(full_path, file_name, PATH_MAX)>= PATH_MAX){
            printk("%s Failed to concatenate file name to directory path\n",modname);
            ret =  false;
            goto free_filename;
        }

        //printk("%s: Adding full path: %s \n",modname,full_path);
        if (d_type == DT_DIR) {         /* subdirectory */
    
            struct file *subdir = filp_open(full_path, O_RDONLY, 0);
            
            if (IS_ERR(subdir)) {
                    printk("%s: error during file opening %s\n", modname, full_path);
                    ret = PTR_ERR(subdir);
                    goto free_filename;
            }

            add_dir(modname, full_path);
                    
        } else {        /* file */

            add_file(modname, full_path);

        }
    }

free_filename:
    kfree(file_name);
free_fullpath:
    kfree(full_path);
free_modname:
    kfree(modname);
    return ret;
}
#else
static int add_entry_actor(struct dir_context *ctx, const char *name, int type, loff_t offset, u64 ino, unsigned d_type) {
	char *full_path;
    char *file_name;

    char last_char;
	// retrieve base dir path from struct custom_dir_context 
	struct my_dir_context *my_ctx = container_of(ctx, struct my_dir_context, dir_ctx);
    int ret = 0;

    char *modname = kstrdup(my_ctx->modname, GFP_KERNEL);
    if (!modname) {
        printk(KERN_ERR "Failed to allocate memory for destination string\n");
        return -ENOMEM;
    }

	// Build full path by using parent directory path passed to iterate_dir and current filename:

    // 1 Copy the path of parent dir and leave the space to append file name 
        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!full_path){
            printk("%s: Can't alloc memory for full path \n",modname);
            ret = -ENOMEM;
            goto free_modname;
           
        }

        strcpy(full_path, my_ctx->dir_path);
        
    // 2 Add the file/directory name to this path
        file_name = kstrdup(name, GFP_KERNEL);
        if (!file_name) {
            printk("%s: Can't alloc memory for file/dir name)\n", modname);
            ret = -ENOMEM;
            goto free_fullpath;
        }

	// exclude current and parent directories 
        if (strcmp(file_name, ".") && strcmp(file_name, "..")) {
        
        // Avoid some broken cases
        if (full_path[0] != '\0')
            last_char = (full_path[strlen(full_path)-1]);
        
        //printk("%s: Adding filename: %s \n",modname,file_name);
        //printk("%s: Last char of %s: %c",modname,full_path,last_char);
        
        // Append the "/" to fullpath
        if( last_char != '/'){
            if(strlcat(full_path, "/", PATH_MAX) >= PATH_MAX){
                printk("%s Failed to append slash to directory path\n",modname);
                ret = -ENOMEM;
                goto free_filename;
            }
        }

        // Append the dir/file name
        if(strlcat(full_path, file_name, PATH_MAX) >= PATH_MAX){
            printk("%s Failed to concatenate file name to directory path\n",modname);
            ret =  -ENOMEM;
            goto free_filename;
        }

        //printk("%s: Adding full path: %s \n",modname,full_path);
        
        if (d_type == DT_DIR) {         /* It's a directory */
    
            struct file *subdir = filp_open(full_path, O_RDONLY, 0);
            
            if (IS_ERR(subdir)) {
                    printk("%s: Error during file opening %s\n", modname, full_path);
                    ret = PTR_ERR(subdir);
                    goto free_filename;
            }

            add_dir(modname, full_path);
                    
        } else {        /* Is a file */

            add_file(modname, full_path);

        }
    }

free_filename:
    kfree(file_name);
free_fullpath:
    kfree(full_path);
free_modname:
    kfree(modname);
    return ret;
}
#endif


int file_in_protected_paths(const char* filename){
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



ino_t get_inode_from_path(const char* percorso){
    struct path path;
    struct dentry *dentry;
    ino_t inode_number;
    int ret;
    char * pathname;

    // Ottieni il percorso del file
    pathname = kstrdup(percorso, GFP_KERNEL);
    if (!pathname) {
        printk(KERN_ERR "Failed to allocate memory for destination string\n");
        return 0;
    }

    ret = kern_path(pathname, LOOKUP_FOLLOW, &path); 
    if (ret == -ENOENT) {
        ret = kern_path(strcat(pathname, "~"), LOOKUP_FOLLOW, &path);
        if (ret){
            //printk("Can't find absolute path");
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

int parent_is_blacklisted(const struct dentry* dentry){
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

/**
 * @brief Get the path from dentry object.
 * 
 * @param dentry 
 * @return char* 
 */
char *get_path_from_dentry(struct dentry *dentry) {
        char *full_path; 
        char *buffer = (char *)__get_free_page(GFP_KERNEL);
        if (!buffer)
            return "";

        full_path = dentry_path_raw(dentry, buffer, PATH_MAX);
        if (IS_ERR(full_path)) {
            printk("Can't find full path: %li", PTR_ERR(full_path));
            free_page((unsigned long)buffer);
            return "";
        } 

        free_page((unsigned long)buffer);

        return full_path;
}

/**
 * @brief Gets the log information and writes them into log_entry
 * 
 * @param entry 
 * @param cmd Specifies the command used on the blacklisted file/dir
 * @return int 
 */
int get_log_info(struct log_entry * entry, char* cmd){
    
    strncpy(entry->cmd, cmd, CMD_SIZE); // Executed CMD
    entry->process_tgid = task_tgid_vnr(current); //process TGID
    entry->thread_id = current->pid; //thread ID
    entry->user_id = current_uid().val; // user-id
    entry->effective_user_id = current_euid().val; //effective user-id
    entry->exe_dentry = current->mm->exe_file->f_path.dentry;
    return 0;
}


/**
 * @brief Get the path and the hash of the program content that touch blacklisted file/dir. 
 * 
 * @param entry 
 * @return int 
 */
int get_path_and_hash(struct log_entry *entry) {
    char *path;
    struct file *file;
    char *file_content;
    int file_size;
    int ret = -1;

    // Retrieve path from exe_dentry
    path = get_path_from_dentry(entry->exe_dentry);
    if (!path || path[0] == '\0') {
        printk("Can't find exe path for: %s\n", entry->exe_dentry->d_name.name);
        return -EINVAL;
    }

    // Copy path to program_path
    strncpy(entry->program_path, path, PATH_MAX);

    // Open the file for reading
    file = filp_open(path, O_RDONLY, 0);
    if (!file || IS_ERR(file)) {
        printk("Failed to open file: %s\n", path);
        ret = -ENOENT;
        goto cleanup;
    }

    // Get the file size
    file_size = i_size_read(file_inode(file));
    if (file_size <= 0) {
        printk("Invalid file size\n");
        ret = -EINVAL;
        goto close_file;
    }

    // Allocate memory for file content
    file_content = kmalloc(file_size, GFP_KERNEL);
    if (!file_content) {
        printk( "Failed to allocate memory for file content\n");
        ret = -ENOMEM;
        goto close_file;
    }

    // Read file content into buffer
    ret = kernel_read(file, file_content, file_size, &file->f_pos);
    if (ret < 0) {
        printk("Failed to read file content\n");
        goto free_memory;
    }

    // Calculate SHA-256 hash of file content
    ret = calculate_sha256(file_content, file_size, entry->file_content_hash);
    if (ret < 0) {
        printk(KERN_ERR "Failed to calculate SHA-256 hash\n");
        goto free_memory;
    }

    // Set return value on success
    ret = 0;

free_memory:
    kfree(file_content);

close_file:
    filp_close(file, NULL);

cleanup:
    kfree(path);
    return ret;
}

/**
 * @brief Evaluate SHA256 and return the result. Used only to get the password to configure monitor.
 * 
 * @param pasw 
 * @return * char* 
 */
char * get_sha(char* pasw){
    char* hash = kmalloc(PASW_MAX_LENGTH, GFP_KERNEL);
    calculate_sha256(pasw,strlen(pasw), hash);
    return hash;
}

/**
 * @brief Function to calculate the SHA-256 hash.
 *
 * This function calculates the SHA-256 hash of the input data and stores the result
 * in the specified output buffer.
 *
 * @param input Pointer to the input data.
 * @param input_len Length of the input data.
 * @param output Pointer to the buffer where the hash will be stored (must be at least 65 bytes long).
 * @return
 *    - 0 if the hash calculation is successful.
 *    - Error code (< 0) if the hash calculation fails.
 */
int calculate_sha256(const char *input, size_t input_len, char *output) {
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    char *hash;
    int ret = 0;
    int i;

    // Allocate memory for the hash buffer
    hash = kmalloc(HASH_MAX_DIGESTSIZE , GFP_ATOMIC);
    if (!hash) {
        printk(KERN_ERR "Failed to allocate hash buffer\n");
        return -ENOMEM;
    }

    // Allocate memory for the transformation object
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate crypto shash\n");
        ret = PTR_ERR(tfm);
        goto free_hash;
    }

    // Allocate memory for the hash descriptor
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_ATOMIC);
    if (!desc) {
        printk(KERN_ERR "Failed to allocate shash descriptor\n");
        ret = -ENOMEM;
        goto free_tfm;
    }

    desc->tfm = tfm;

    // Initialize the hash descriptor
    ret = crypto_shash_init(desc);
    if (ret) {
        printk(KERN_ERR "Failed to initialize crypto shash\n");
        goto free_desc;
    }

    // Add the data to be hashed
    ret = crypto_shash_update(desc, input, input_len);
    if (ret) {
        printk(KERN_ERR "Failed to update crypto shash\n");
        goto free_desc;
    }

    // Finalize the hash calculation
    ret = crypto_shash_final(desc, hash);
    if (ret) {
        printk(KERN_ERR "Failed to finalize crypto shash\n");
        goto free_desc;
    }

    // Copy the hash to the output buffer in hexadecimal format
    for (i = 0; i < crypto_shash_digestsize(tfm); i++) {
        snprintf(output + (i * 2), 3, "%02x", (unsigned int)hash[i] & 0xFF);
    }

free_desc:
    kfree(desc);
free_tfm:
    crypto_free_shash(tfm);
free_hash:
    kfree(hash);

    return ret;
}


/**
 * @brief Write the entry inside the log file.
 * 
 * @param entry 
 * @return int 
 */
int write_log_entry(struct log_entry* entry) {
    struct file *log_file;
    ssize_t ret = -1;
    char log_data[256];

    // Just for debug
    //print_log_entry(entry);

    // Open log file
    log_file = filp_open(LOG_PATH, O_WRONLY, 0644);
    if (IS_ERR(log_file)) {
        int err = PTR_ERR(log_file);
        printk(KERN_ERR "Failed to open log file: %d\n", err);
        ret = err;
        goto cleanup;
    }

    // Format file string
    snprintf(log_data, sizeof(log_data), "|| %s || %d || %d || %u || %u || %s - %s ||\n",
        entry->cmd, entry->thread_id, entry->process_tgid, entry->user_id,
        entry->effective_user_id, entry->program_path, entry->file_content_hash);
    
   
    ret = kernel_write(log_file, log_data, strlen(log_data), &log_file->f_pos);
    if (ret < 0) {
        printk(KERN_ERR "Failed to write on file %ld \n",ret);
    }

cleanup:
    // Close the log file if it was successfully opened
    if (log_file && !IS_ERR(log_file)) {
        filp_close(log_file, NULL);
    }


    return ret;
}


/**
 * @brief Just a debugging function, it prints the various entry to the log.
 * 
 * @param entry 
 */
void print_log_entry(struct log_entry *entry) {
    if (!entry) {
        printk(KERN_ERR "Entry pointer is NULL\n");
        return;
    }

    printk(KERN_INFO "Command: %s\n", entry->cmd);
    printk(KERN_INFO "Process TGID: %d\n", entry->process_tgid);
    printk(KERN_INFO "Thread ID: %d\n", entry->thread_id);
    printk(KERN_INFO "User ID: %d\n", entry->user_id);
    printk(KERN_INFO "Effective User ID: %d\n", entry->effective_user_id);
    printk(KERN_INFO "Program Path: %s\n", entry->program_path);
    printk(KERN_INFO "File Content Hash: %s\n", entry->file_content_hash);
}