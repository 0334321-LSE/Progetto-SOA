#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h> // Include for PATH_MAX constant


#define OUTPUT_BUFFER_SIZE ((PATH_MAX + 1) * 1000)

// Existing path (a directory that will add more files) to add
#define PATH_TO_ADD "/home/xave/Scrivania/Prova/"

// The monitor password
#define PASSW  "soa"

// Define the number of threads
#define NUM_THREADS  512

// Add a directory path and its own sub files/dir to the monitor
void *add_path(void *thread_id) {
    // Get the thread ID
    int tid = *((int *)thread_id);

    sleep(0.5);

    // Call the system call with path, password, mod and recursive
    long ret = syscall(174,PATH_TO_ADD,PASSW,0,1); 
    if(ret){
        printf("\n---------------------------- \n");
    	perror("Error when adding path");
    }else{
        printf("\n---------------------------- \n");
        perror("Path added");       
    }



    pthread_exit(NULL);
}

// Remove all the paths from the monitor.
void *remove_path(void *args) {
    
    sleep(0.5);

    // Call the system call with password
    long ret = syscall(183,PASSW);
    // Call the function to rename the log file
    if (ret) {
        printf("\n---------------------------- \n");
        perror("Error when removing paths");
    } else {
        printf("\n---------------------------- \n");
        printf("Paths removed successfully\n");
    }

    pthread_exit(NULL);
}

// Function to write to the log file by using open
void *print_paths(void *thread_id) {
    // Get the thread ID
    int tid = *((int *)thread_id);

    sleep(0.5);

    char* output; // More than 1000 path maybe are to much 

    // Dynamically allocate memory for the output buffer
    output = (char *)malloc(OUTPUT_BUFFER_SIZE * sizeof(char));
    if (output == NULL) {
        printf("Failed to allocate memory for output buffer.\n");
        goto exit;
    }

    // Initialize the output buffer to zeros
    memset(output, 0, OUTPUT_BUFFER_SIZE);

    // Call the system call with password
    long ret = syscall(182,output,OUTPUT_BUFFER_SIZE);
    int size = (strlen(output));
    // Check the return value of the system call
    if (ret == 0) {
        printf("\n---------------------------- \n");
        printf("The existing paths are: \n %s",output);
    } else {
        printf("\n---------------------------- \n");
        printf("Failed to get paths.\n");
    }
exit:
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
        module = (i+1) % 3;
        switch(module){
            case 1:
                if (pthread_create(&threads[i], NULL, add_path, (void *)&thread_ids[i]) != 0) {
                    perror("Error creating write_rename thread");
                    return EXIT_FAILURE;
                }
                break;
            case 2:
                if (pthread_create(&threads[i], NULL, remove_path, (void *)&thread_ids[i]) != 0) {
                    perror("Error creating read thread");
                    return EXIT_FAILURE;
                }
                break;

            default:
                if (pthread_create(&threads[i], NULL, print_paths, (void *)&thread_ids[i]) != 0) {
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
