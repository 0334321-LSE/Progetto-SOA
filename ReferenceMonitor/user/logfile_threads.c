#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

// Define the path to the log file
#define BLACKLISTED_FILE "/home/xave/Scrivania/Prova/prova.txt"
#define LOG_FILE  "/mnt/monitor-fs/the-log"

// Define the number of threads
#define NUM_THREADS  512
// Function to write to the log file by using unlink
void *write_to_log_by_unlink(void *thread_id) {
    // Get the thread ID
    int tid = *((int *)thread_id);

    sleep(0.5);

    int result = unlink(BLACKLISTED_FILE); 
    if(result){
    	perror("Cannot unlink file");
    }else
	    perror("File unlinked");
    pthread_exit(NULL);
}

// Function to rename the log file
void *write_to_log_by_rename(void *args) {
    const char *newFilename = "prova.txt";

    sleep(0.5);

    // Call the function to rename the log file
    if (rename(BLACKLISTED_FILE, newFilename) != 0) {
        perror("Error renaming file");
    } else {
        printf("File renamed successfully\n");
    }

    pthread_exit(NULL);
}

// Function to write to the log file by using open
void *write_to_log_by_open(void *thread_id) {
    // Get the thread ID
    int tid = *((int *)thread_id);

    sleep(0.5);

    // Open the log file for appending
    int fd = open(BLACKLISTED_FILE, O_WRONLY | O_APPEND);
    if (fd == -1) {
        perror("Error opening log file");
        pthread_exit(NULL);
    }

    // Prepare the log message
    char log_message[100];
    snprintf(log_message, sizeof(log_message), "Thread %d is writing to the log file\n", tid);

    // Write to the log file
    ssize_t bytes_written = write(fd, log_message, strlen(log_message));
    if (bytes_written == -1) {
        perror("Error writing to log file");
        close(fd);
        pthread_exit(NULL);
    }

    // Close the log file
    close(fd);

    pthread_exit(NULL);
}

// Function to read from the log file
void *read_from_log(void *thread_id) {
    // Get the thread ID
    int tid = *((int *)thread_id);

    sleep(0.5);
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
    int module;
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, NUM_THREADS-1);
    // Create threads for writing
    for (int i = 0; i < NUM_THREADS; ++i) {
        thread_ids[i] = i+1 ;
        module = (i+1) % 4;
        switch(module){
            case 1:
                if (pthread_create(&threads[i], NULL, write_to_log_by_open, (void *)&thread_ids[i]) != 0) {
                    perror("Error creating write_rename thread");
                    return EXIT_FAILURE;
                }
                break;
            case 2:
                if (pthread_create(&threads[i], NULL, write_to_log_by_unlink, (void *)&thread_ids[i]) != 0) {
                    perror("Error creating read thread");
                    return EXIT_FAILURE;
                }
                break;
            case 3:
                if (pthread_create(&threads[i], NULL, write_to_log_by_rename, (void *)&thread_ids[i]) != 0) {
                    perror("Error creating write_open thread");
                    return EXIT_FAILURE;
                }
                break;
            default:
                if (pthread_create(&threads[i], NULL, read_from_log, (void *)&thread_ids[i]) != 0) {
                    perror("Error creating write_unlink thread");
                    return EXIT_FAILURE;
                }
                break;
        }
                    
    }
    pthread_barrier_wait(&barrier); // Synchronize threads at the beginning

    // Join threads
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_join(threads[i], NULL) != 0) {
            perror("Error joining thread");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
