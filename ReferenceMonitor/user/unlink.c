#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    const char *filename = "/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt";

    // Esegue l'operazione di rimozione del file
    int result = unlink(filename);

    if (result == -1) {
        perror("Errore nella rimozione del file");
        exit(EXIT_FAILURE);
    } else {
        printf("Il file è stato rimosso con successo.\n");
    }

    return 0;
}
