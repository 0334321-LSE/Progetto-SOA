#include "reference_monitor.h"

// Implementazione dell'operazione di inizializzazione del monitor
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

