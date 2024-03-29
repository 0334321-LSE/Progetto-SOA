#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define FILE_PATH "../mount/the-log"  // Path al file system creato

int main() {
    int fd;
    const char *data = "Nuovi dati da aggiungere al file!\n";

    // Apertura del file in modalità append only
    fd = open(FILE_PATH, O_WRONLY | O_APPEND);
    if (fd == -1) {
        perror("Errore nell'apertura del file");
        exit(EXIT_FAILURE);
    }

    // Scrittura dei dati nel file
    if (write(fd, data, strlen(data)) == -1) {
        perror("Errore nella scrittura nel file");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Chiusura del file
    if (close(fd) == -1) {
        perror("Errore nella chiusura del file");
        exit(EXIT_FAILURE);
    }

    printf("Dati aggiunti al file con successo!\n");

    return 0;
}