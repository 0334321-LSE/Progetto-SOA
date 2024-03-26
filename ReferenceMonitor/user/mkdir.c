#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

int main() {
    const char *directory = "./test/new_directory/";

    // Creiamo una nuova directory
    int result = mkdir(directory, 0777); // Imposta i permessi della nuova directory a 777

    if (result == -1) {
        perror("Errore nella creazione della directory");
        exit(EXIT_FAILURE);
    } else {
        printf("La directory è stata creata con successo.\n");
    }

    return 0;
}
