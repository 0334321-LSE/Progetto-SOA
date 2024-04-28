#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <limits.h> // Include for PATH_MAX constant

#define OUTPUT_BUFFER_SIZE ((PATH_MAX + 1) * 1000)
#define LOG_PATH "/mnt/monitor-fs/the-log"
#define STATE_MAX_LENGTH 16

int get_integer_input(const char *prompt);
void execute_sys_state_update();
void execute_sys_configure_path_add();
void execute_sys_configure_path_add_recursive();
void execute_sys_configure_path_remove();
void execute_sys_remove_all_paths();
void execute_sys_print_paths();
void print_monitor_log();
int get_state(char * state);
void execute_command(int command);
void fix_output();
int read_input(char *buffer, size_t size);

// Function to read a line of input using fgets and remove trailing newline
int read_input(char *buffer, size_t size) {
    if (buffer == NULL || size == 0) {
        printf("Invalid argument...\n");
        return 0; // Invalid arguments
    }

    if (fgets(buffer, size, stdin) != NULL) {
        // Check if last character is a newline (\n)
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0'; // Remove newline by replacing with null terminator
        } else {
            // Input exceeded buffer size or no newline found (input too large)
            printf("Input too big, exit...\n");
            return 0; // Return 0 to indicate failure (input too big)
        }
        return 1; // Return 1 to indicate success (input read)
    } else {
        printf("An error occured, exit...\n");
        return 0; // Error reading input
    }
}

// Function to execute the chosen command
void execute_command(int command) {
    // Execute the command based on the user's choice
    switch (command) {
        case 1: 
            printf("---------------------------- \n");
            printf("- Changing monitor state - \n");
            execute_sys_state_update();
            break;
        case 2:
            printf("---------------------------- \n");
            printf("- Adding one path - \n");
            execute_sys_configure_path_add();
            break;
        case 3:
            printf("---------------------------- \n");
            printf("- Adding path recursive - \n");
            execute_sys_configure_path_add_recursive();
            break;
        case 4:
            printf("---------------------------- \n");
            printf("- Removing one path - \n");
            execute_sys_configure_path_remove();
            break;
        case 5:
            printf("---------------------------- \n");
            printf("- Removing all paths - \n");
            execute_sys_remove_all_paths();
            break;
        case 6:
            printf("---------------------------- \n");
            printf("- Printing monitored paths - \n");
            execute_sys_print_paths();
            break;
        case 7:
            printf("---------------------------- \n");
            printf("- Printing monitor log - \n");
            print_monitor_log();
            break;      
            
        default:
            printf("---------------------------- \n");
            printf("Invalid command\n");
    }

    // Wait for user input before exiting
    printf("\nSend any key to continue...\n");
    getchar(); // Wait for Enter key press
}

// Function to prompt and get a valid integer input from the user
int get_integer_input(const char *prompt) {
   char input;
    int digit_value;
    int is_valid = 0;

    while (!is_valid) {
        printf("%s ",prompt);

        // Read a single character from stdin
        if (scanf(" %c", &input) != 1 || !isdigit(input) || getchar() != '\n') {
            // If scanf failed to read a character or the input is not a digit or there are additional characters in the input buffer
            printf("Error: Invalid input. Please enter a single digit (0-7).\n");

            // Clear input buffer by reading and discarding remaining characters up to newline
            while (getchar() != '\n'); // Clear stdin buffer
        } else {
            // Valid input: Convert char to integer value
            digit_value = input - '0';
            is_valid = 1; // Set flag to exit loop
        }
    }

    return digit_value;
}


// Function to execute sys_state_update system call
void execute_sys_state_update() {
    char state[STATE_MAX_LENGTH]; // Buffer for state
    char password[65]; // Buffer for password

    // Prompt user for state input and validate
    while (1) {
        printf("Enter state (ON, OFF, REC-ON, REC-OFF): ");
                
        if(!read_input(state,sizeof(state)))
            goto exit;

        // Validate state input
        if (strcmp(state, "ON") == 0 || strcmp(state, "OFF") == 0 ||
            strcmp(state, "REC-ON") == 0 || strcmp(state, "REC-OFF") == 0) {
            break; // Input is valid, exit loop
        } else {
            printf("Invalid state. Please enter a valid state.\n");
        }
    }

    // Prompt user for password input
    printf("Enter password: ");
    if(!read_input(password,sizeof(password)))
        goto exit;
    
    // Call the system call with state and password
    long ret = syscall(134,&state,&password);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }
exit:
    printf("---------------------------- \n");
}

// Function to execute sys_configure_path system call in add mode
void execute_sys_configure_path_add() {
    char path[PATH_MAX]; // Buffer for path
    char password[65]; // Buffer for password

    while(1){
        // Prompt user for path input
        printf("Enter path: ");
        if(!read_input(path,sizeof(path)))
            goto exit;

        // Check if the path is absolute
        if (path[0] != '/') 
            printf("Error: Path must be absolute.\n");
        else{
            if (strlen(path)==1)
                printf("Error: Can't black list: '/' \n");
            else
                break;
        }

    }

    // Prompt user for password input
    printf("Enter password: ");
    if(!read_input(password,sizeof(password)))
        goto exit;

    // Call the system call with path, password, mod and recursive
    long ret = syscall(174,&path,&password,0,0);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }

exit:
    printf("---------------------------- \n");
}

// Function to execute sys_configure_path system call in add recursive mode
void execute_sys_configure_path_add_recursive() {
    char path[PATH_MAX]; // Buffer for path
    char password[65]; // Buffer for password

    while(1){
        // Prompt user for path input
        printf("Enter path: ");
        if(!read_input(path,sizeof(path)))
            goto exit;

        // Check if the path is absolute
        if (path[0] != '/') 
            printf("Error: Path must be absolute.\n");
        else{
            if (strlen(path)==1)
                printf("Error: Can't black list: '/' \n");
            else
                break;
        }
    }

    // Prompt user for password input
    printf("Enter password: ");
    if(!read_input(password,sizeof(password)))
        goto exit;

    // Call the system call with path, password, mod and recursive
    long ret = syscall(174,&path,&password,0,1);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }

exit:
    printf("---------------------------- \n");
}

// Function to execute sys_configure_path system call in rmv mode
void execute_sys_configure_path_remove() {
    char path[PATH_MAX]; // Buffer for path
    char password[65]; // Buffer for password

    while(1){
        // Prompt user for path input
        printf("Enter path: ");
        if(!read_input(path,sizeof(path)))
            goto exit;

        // Check if the path is absolute
        if (path[0] != '/') 
            printf("Error: Path must be absolute.\n");
        else
            break;
    }

    // Prompt user for password input
    printf("Enter password: ");
    if(!read_input(password,sizeof(password)))
        goto exit;

    // Call the system call with path, password, and mod
    long ret = syscall(174,&path,&password,1);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }
exit:
    printf("---------------------------- \n");

}

// Function to execute sys_remove_all_paths system call
void execute_sys_remove_all_paths() {
    char password[65]; // Buffer for password

    // Prompt user for password input
    printf("Enter password: ");
    if(!read_input(password,sizeof(password)))
        goto exit;

    // Call the system call with password
    long ret = syscall(183,&password);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }

exit:
    printf("---------------------------- \n");

}

// Function to execute sys_print_paths system call
void execute_sys_print_paths() {
    char* output; // More than 1000 path maybe are to much 

    // Dynamically allocate memory for the output buffer
    output = (char *)malloc(OUTPUT_BUFFER_SIZE * sizeof(char));
    if (output == NULL) {
        printf("Failed to allocate memory for output buffer.\n");
        return;
    }

    // Initialize the output buffer to zeros
    memset(output, 0, OUTPUT_BUFFER_SIZE);

    // Call the system call with password
    long ret = syscall(182,output,OUTPUT_BUFFER_SIZE);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
        printf("---------------------------- \n");

        printf("The existing paths are: \n %s",output);
    } else {
        printf("---------------------------- \n");
        printf("Failed to execute system call.\n");
    }

}

void print_monitor_log(){
    // Execute the cat command to display the contents of the file
    char command[256];  // Define a buffer to hold the command string

    // Format the command string with the specified LOG_PATH
    snprintf(command, sizeof(command), "cat %s", LOG_PATH);

    // Execute the command using system
    system(command);

    printf("\n---------------------------- \n");
}

int get_state(char * state){
    return syscall(214,state);
}

void fix_output(){
    int c;
    // Flush stdin
    while ((c = getchar()) != '\n' && c != EOF) {
        // Discard characters
    }
}

int main(int argc, char** argv){
    int command;
    int c;
    char* current_state = (char *) malloc(STATE_MAX_LENGTH * sizeof(char));

    while (1) {
        system("clear");
        if(get_state(current_state)){
            printf("\n Monitor isn't installed, exiting ...\n");
            sleep(1);
            goto exit;
        }

        // Display the menu
        printf("\n---- Reference Monitor Menu ----\n");
        printf("\n---- Monitor current state: %s ----\n\n",current_state);

        printf("1 | Change monitor state \n");
        printf("2 | Add one path \n");
        printf("3 | Add path recursive \n");
        printf("4 | Remove one path \n");
        printf("5 | Remove all paths \n");
        printf("6 | Print all paths \n");
        printf("7 | Print monitor log \n");
        printf("0 | To exit \n");

        
        // Get a valid integer input for the command
        command = get_integer_input("Choose a command: ");

        // Check if the command is the exit command
        if (command == 0) {
            printf("Exiting the program...\n");
            sleep(1);
            system("clear");

            break; // Exit the loop
        }

        // Execute the chosen command
        execute_command(command);
        // Flush stdin
        while ((c = getchar()) != '\n' && c != EOF) {
            // Discard characters
        }
    }
exit:
    return 0;
}
