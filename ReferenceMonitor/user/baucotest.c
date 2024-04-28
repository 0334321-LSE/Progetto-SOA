#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NUM_THREADS 500
#define FILENAME "/home/xave/Scrivania/Prova/prova.txt"

void *thread_function(void *arg) {
    
    int fd = open(FILENAME, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd) {
        perror("Error in write-opening the file");
    } else {
        printf("File %s write-opened\n", FILENAME);
        close(fd);
    }

    if (rename(FILENAME, "rename.txt")) {
        perror("Error in file renaming");
    } else {
        printf("File %s successfully renamed\n", FILENAME);
    }

    if (unlink(FILENAME)) {
        perror("Error in file deletion");
    } else {
        printf("File %s successfully deleted\n", FILENAME);
    }
}

int main() {
    pthread_t threads[NUM_THREADS];
    int thread_args[NUM_THREADS];
    int i, result;

    for (i = 0; i < NUM_THREADS; i++) {
        thread_args[i] = i;
        result = pthread_create(&threads[i], NULL, thread_function, &thread_args[i]);
        if (result) {
            fprintf(stderr, "Error in creating thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    for (i = 0; i < NUM_THREADS; i++) {
        result = pthread_join(threads[i], NULL);
        if (result) {
            fprintf(stderr, "Errore in waiting thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}