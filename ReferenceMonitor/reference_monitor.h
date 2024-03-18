#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#include <linux/list.h>
#include <linux/spinlock.h>  
#include <linux/slab.h> 
#include <linux/string.h>

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
    struct list_head list;  // Nodo per la lista collegata
};

struct reference_monitor {
    enum State state;  // Stato del monitor 
    struct list_head protected_paths;
    char* password;
    spinlock_t lock;
};

int file_in_protected_paths(const char* filename);
#endif /* REFERENCE_MONITOR_H */