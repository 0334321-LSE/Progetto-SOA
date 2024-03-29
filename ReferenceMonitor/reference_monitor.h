#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#include <linux/list.h>
#include <linux/spinlock.h>  
#include <linux/slab.h> 
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/vfs.h>
#include <linux/path.h>
#include <linux/namei.h>


// MAX PASW SIZE
#define PASW_MAX_LENGTH 64
#define STATE_MAX_LENGTH 16

extern struct reference_monitor* monitor;

enum State {
    OFF,
    REC_OFF,
    ON,
    REC_ON
};

struct protected_path{
    char* path_name; 
    ino_t inode_number;
    struct list_head list;  // Nodo per la lista collegata
};

struct reference_monitor {
    enum State state;  // Stato del monitor 
    struct list_head protected_paths;
    char* password;
    spinlock_t lock;
};

struct my_dir_context{
    struct dir_context dir_ctx; 
    char *dir_path;
    char *modname;
};

inline int file_in_protected_paths(const char* filename);
inline ino_t get_inode_from_path(const char* path);
inline int inode_in_protected_paths(long unsigned int inode_number);
inline int add_file(char* modname, const char* path);
inline int add_dir(char* modname, const char* path);
inline int is_directory(const char *path);
inline int parent_is_blacklisted(const struct dentry* dentry);

#endif /* REFERENCE_MONITOR_H */