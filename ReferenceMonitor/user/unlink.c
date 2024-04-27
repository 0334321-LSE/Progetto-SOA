#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    const char *filename = "/home/xave/Scrivania/Prova/prova.txt";
    int result;
    int i = 0;
    while(1){
        // Esegue l'operazione di rimozione del file
        result = unlink(filename);
        i++;
        if (result == -1) {
            perror("Errore nella rimozione del file");

        } else {
            printf("Il file è stato rimosso con successo.\n");
        }
        if(i==1000){
            return 0;
        }
    }
    return 0;
}
