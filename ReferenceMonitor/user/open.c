#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int main() {
    const char *filename = "/media/sf_shared-dir/Progetto-SOA/ReferenceMonitor/user/test.txt";
    int file_descriptor;

    // Apre il file in modalità scrittura (O_WRONLY) e lo crea se non esiste (O_CREAT)
    // e tronca il file a lunghezza zero se esiste già (O_TRUNC)
    // Il flag O_CREAT richiede un parametro aggiuntivo per specificare i permessi del file
    // In questo caso, 0644 indica che il file sarà creato con permessi rw-r--r--
    file_descriptor = open(filename, O_WRONLY | O_TRUNC, 0644);

    if (file_descriptor == -1) {
        perror("Errore nell'apertura del file");
        exit(EXIT_FAILURE);
    } else {
        printf("Il file è stato aperto con successo in modalità scrittura.\n");

        // Operazione di scrittura
        const char *message = "Questo è un test di scrittura.\n";
        ssize_t bytes_written = write(file_descriptor, message, strlen(message));

        if (bytes_written == -1) {
            perror("Errore nella scrittura sul file");
            close(file_descriptor);
            exit(EXIT_FAILURE);
        } else {
            printf("Scrittura sul file completata con successo.\n");
        }

        // Chiude il file descriptor dopo aver finito di lavorare con il file
        close(file_descriptor);
        printf("Il file è stato chiuso correttamente.\n");
    }

    return 0;
}
