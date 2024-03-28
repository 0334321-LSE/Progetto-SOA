#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int try_rename(const char* file,const char* new_file);
int try_unlink(const char* file);

int main() {
    const char *file_path = "/home/xave/Desktop/Prova/test.txt";
    const char *hard_link_path = "/home/xave/Desktop/Prova/hard_link.txt";

    // Hard link creation
    if (link(file_path, hard_link_path) == -1) {
        perror("Errore during hard link creation");
        exit(EXIT_FAILURE);
    }
    printf("hard link '%s' for '%s' succesfully created \n", hard_link_path, file_path);
    try_rename(hard_link_path, "/home/xave/Desktop/Prova/nuovo_nome.txt");
    unlink(hard_link_path);

    return 0;
}

int try_rename(const char* file,const char* new_file){

    // Eseguiamo l'operazione di rinomina della directory
    int result = rename(file, new_file);

    if (result == -1) {
        perror("Error during renaming");
        exit(EXIT_FAILURE);
    } else {
        printf("File renaming success.\n");
    }

    return 0;
}

int try_unlink(const char* file){
       
    int result = unlink(file);

    if (result == -1) {
        perror("Errore during file unlink");
        exit(EXIT_FAILURE);
    } else {
        printf("File unlink sucess.\n");
    }

    return 0;
}