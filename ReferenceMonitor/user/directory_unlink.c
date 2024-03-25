#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    const char *directory = "/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test";

    // Eseguiamo l'operazione di rimozione della directory
    int result = rmdir(directory);

    if (result == -1) {
        perror("Errore nella rimozione della directory");
        exit(EXIT_FAILURE);
    } else {
        printf("La directory è stata rimossa con successo.\n");
    }

    return 0;
}