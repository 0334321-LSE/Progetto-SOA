#include "reference_monitor.h"

int file_in_protected_paths(const char* filename){
    struct protected_path *entry;
    // Acquisisci la spinlock per accedere alla lista dei percorsi protetti
    /*printk("%s: LOCK \n","refmon");
    spin_lock(&monitor->lock);*/

    // Iterate on the list, *_safe is not required is needed only for removes
    list_for_each_entry(entry, &monitor->protected_paths, list){
        // strncmp more secure in respect of strcmp, prevents buffer overflow
        if (strncmp(entry->path_name, filename, strlen(entry->path_name)) == 0) {
            // Il percorso è presente nella lista dei percorsi protetti
            /*spin_unlock(&monitor->lock);
            printk("%s: UNLOCK \n","refmon");*/

            return 1;
        }

    }

    // Rilascia la spinlock
    /*spin_unlock(&monitor->lock);
    printk("%s: UNLOCK \n","refmon");*/

    // Il percorso non è presente nella lista dei percorsi protetti
    return 0;
}

