#include "reference_monitor.h"

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

inline int file_in_protected_paths(const char* filename){
    struct protected_path *entry;
    ino_t inode_number;
    // Acquisisci la spinlock per accedere alla lista dei percorsi protetti
    //spin_lock(&monitor->lock);

    inode_number = get_inode_from_path(filename);
    if (inode_number == 0)
        //not valid path
        return 0;

    // Iterate on the list, *_safe is not required is needed only for removes
    list_for_each_entry(entry, &monitor->protected_paths, list){
        // strncmp more secure in respect of strcmp, prevents buffer overflow
        if (entry->inode_number == inode_number) {
            // Il percorso è presente nella lista dei percorsi protetti
            //spin_unlock(&monitor->lock);

            return 1;       
        }
    }

    // Rilascia la spinlock
    //spin_unlock(&monitor->lock);

    // Il percorso non è presente nella lista dei percorsi protetti
    return 0;
}


inline ino_t get_inode_from_path(const char* percorso){
    struct path path;
    struct dentry *dentry;
    ino_t inode_number;

    // Ottieni il percorso del file
    if (kern_path(percorso, LOOKUP_FOLLOW, &path)) {
        // Gestione dell'errore
        return 0; // Inode invalido
    }

    dentry = path.dentry;

    // Ottieni l'inode del file
    inode_number = dentry->d_inode->i_ino;

    path_put(&path);

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