#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Define the path to the log file
#define BLACLISTED_FILE "/home/xave/Scrivania/Prova/prova.txt"
#define LOG_FILE  "/mnt/monitor-fs/the-log"

// Define the number of threads
#define NUM_THREADS 16

// Function to write to the log file
void *write_to_log(void *thread_id) {
    // Get the thread ID
    int tid = *((int *)thread_id);

    // Open the log file for appending
    FILE *file = fopen(BLACLISTED_FILE, "a");
    if (file == NULL) {
        perror("Error opening log file");
        pthread_exit(NULL);
    }

    // Write to the log file
    fprintf(file, "Thread %d is writing to the log file\n", tid);

    // Close the log file
    fclose(file);

    pthread_exit(NULL);
}

// Function to read from the log file
void *read_from_log(void *thread_id) {
    // Get the thread ID
    int tid = *((int *)thread_id);

    // Open the log file for reading
    FILE *file = fopen(LOG_FILE, "r");
    if (file == NULL) {
        perror("Error opening log file");
        pthread_exit(NULL);
    }

    // Read from the log file
    char line[256];
    fgets(line, sizeof(line), file);
    printf("Thread %d is reading: %s", tid, line);
    

    // Close the log file
    fclose(file);

    pthread_exit(NULL);
}

int main() {
    // Create an array to hold thread IDs
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    // Create threads for writing
    for (int i = 0; i < NUM_THREADS; ++i) {
        thread_ids[i] = i + 1;
        if(i%2 == 0){
            if (pthread_create(&threads[i], NULL, write_to_log, (void *)&thread_ids[i]) != 0) {
                perror("Error creating write thread");
                return EXIT_FAILURE;
            }
        }
        else{
            if (pthread_create(&threads[i], NULL, read_from_log, (void *)&thread_ids[i]) != 0) {
                perror("Error creating read thread");
                return EXIT_FAILURE;
            }
        }
    }

    // Join threads
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_join(threads[i], NULL) != 0) {
            perror("Error joining thread");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
