#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#include <linux/list.h>
#include <linux/spinlock.h>  
#include <linux/slab.h> 
#include <linux/string.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/vfs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>

// MAX PASW SIZE
#define PASW_MAX_LENGTH 65
#define HASH_SIZE 65
#define STATE_MAX_LENGTH 16
#define CMD_SIZE 5
#define LOG_PATH "/mnt/monitor-fs/the-log"
#define OUTPUT_BUFFER_SIZE ((PATH_MAX + 1) * 1000)


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

struct log_entry {
    char  cmd[CMD_SIZE]; // Command
    pid_t process_tgid;  // Process TGID
    pid_t thread_id;     // Thread ID
    uid_t user_id;       // User ID
    uid_t effective_user_id;  // Effective User ID
    char program_path[PATH_MAX];   // Program Path Name
    char file_content_hash[HASH_SIZE]; // Cryptographic Hash of Program File Content (SHA-256)
    struct dentry* exe_dentry;
};

int file_in_protected_paths(const char* filename);
ino_t get_inode_from_path(const char* path);
int inode_in_protected_paths(long unsigned int inode_number);
int add_file(char* modname, const char* path);
int add_dir(char* modname, const char* path);
int is_directory(const char *path);
int parent_is_blacklisted(const struct dentry* dentry);
char * get_sha(char* paswd);
int get_log_info(struct log_entry * entry, char* cmd);
int get_path_and_hash(struct log_entry *entry);
int write_log_entry(struct log_entry * entry);

#endif /* REFERENCE_MONITOR_H */