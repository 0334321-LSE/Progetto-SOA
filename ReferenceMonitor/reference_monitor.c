#include "reference_monitor.h"

// Implementazione dell'operazione di inizializzazione del monitor
/*
int reference_monitor_init(struct reference_monitor* monitor, char* password) {
    INIT_LIST_HEAD(&monitor->protected_paths);  // Inizializza la lista dei percorsi protetti
    spin_lock_init(&monitor->lock);  // Inizializza lo spinlock

    // Imposta lo stato iniziale del monitor (OFF)
    monitor->state = OFF;

    // Inizializza il campo della password 
    monitor->password = kstrdup(password, GFP_KERNEL);
    if (!monitor->password)
        return -ENOMEM;  // Errore di memoria

    return 0;  // Successo
}

// Implementazione dell'operazione di release del monitor
void reference_monitor_cleanup(struct reference_monitor* monitor) {
    struct protected_path *entry, *tmp;

    // Libera tutti i percorsi protetti nella lista
    spin_lock(&monitor->lock);
    list_for_each_entry_safe(entry, tmp, &monitor->protected_paths, list) {
        list_del(&entry->list);
        kfree(entry);
    }

    // Dealloca la memoria per la password
    kfree(monitor->password);
    spin_unlock(&monitor->lock);
}
*/

int file_in_protected_paths(char* filename){
    struct protected_path *entry;
    // Acquisisci la spinlock per accedere alla lista dei percorsi protetti
    spin_lock(&monitor->lock);
    // Scorrere la lista dei percorsi protetti
    list_for_each_entry(entry, &monitor->protected_paths, list) {
        // Confronta il percorso del file con il percorso nella lista
        if (strcmp(entry->path_name, filename) == 0) {
            // Il percorso è presente nella lista dei percorsi protetti
            spin_unlock(&monitor->lock);
            return 1;
        }

    }

    // Rilascia la spinlock
    spin_unlock(&monitor->lock);
    // Il percorso non è presente nella lista dei percorsi protetti
    return 0;
}

