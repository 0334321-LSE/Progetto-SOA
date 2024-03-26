#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *old_directory = "/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test/";
    const char *new_directory = "/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/new_test/";

    // Eseguiamo l'operazione di rinomina della directory
    int result = rename(old_directory, new_directory);

    if (result == -1) {
        perror("Errore nella rinomina della directory");
        exit(EXIT_FAILURE);
    } else {
        printf("La directory è stata rinominata con successo.\n");
    }

    return 0;
}