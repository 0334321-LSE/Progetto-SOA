#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <limits.h> // Include for PATH_MAX constant

#define OUTPUT_BUFFER_SIZE ((PATH_MAX + 1) * 1000)

int get_integer_input(const char *prompt);
void execute_sys_state_update();
void execute_sys_configure_path_add();
void execute_sys_configure_path_add_recursive();
void execute_sys_configure_path_remove();
void execute_sys_remove_all_paths();
void execute_sys_print_paths();
void print_monitor_log();
void get_state(char * state);
void execute_command(int command);
void fix_output();

// Function to execute the chosen command
void execute_command(int command) {
    // Execute the command based on the user's choice
    switch (command) {
        case 1: 
            printf("---------------------------- \n");
            printf("- Changing monitor state - \n");
            execute_sys_state_update();
            fix_output();
            break;
        case 2:
            printf("---------------------------- \n");
            printf("- Adding one path - \n");
            execute_sys_configure_path_add();
            fix_output();
            break;
        case 3:
            printf("---------------------------- \n");
            printf("- Adding path recursive - \n");
            execute_sys_configure_path_add_recursive();
            fix_output();
            break;
        case 4:
            printf("---------------------------- \n");
            printf("- Removing one path - \n");
            execute_sys_configure_path_remove();
            fix_output();
            break;
        case 5:
            printf("---------------------------- \n");
            printf("- Removing all paths - \n");
            execute_sys_remove_all_paths();
            fix_output();
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
    int input = -1;
    char buffer[100]; // Buffer for user input

    while (1) {
        printf("%s", prompt);
        fgets(buffer, sizeof(buffer), stdin);

        // Remove newline character from the input
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }

        // Check if input is a valid integer
        int valid = 1;
        for (size_t i = 0; i < strlen(buffer); i++) {
            if (!isdigit(buffer[i])) {
                valid = 0;
                break;
            }
        }

        // If input is valid, convert it to an integer and return
        if (valid) {
            input = atoi(buffer);
            break;
        } else {
            printf("Invalid input. Please enter a valid integer.\n");
        }
    }

    return input;
}

// Function to execute sys_state_update system call
void execute_sys_state_update() {
    char state[10]; // Buffer for state
    char password[65]; // Buffer for password

    // Prompt user for state input and validate
    while (1) {
        printf("Enter state (ON, OFF, REC-ON, REC-OFF): ");
        scanf("%9s", state); // Limit input to 9 characters to prevent buffer overflow

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
    scanf("%64s", password); // Limit input to 64 characters to prevent buffer overflow

    // Call the system call with state and password
    long ret = syscall(134,&state,&password);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }
    printf("---------------------------- \n");

}

// Function to execute sys_configure_path system call in add mode
void execute_sys_configure_path_add() {
    char path[PATH_MAX]; // Buffer for path
    char password[65]; // Buffer for password

    while(1){
        // Prompt user for path input
        printf("Enter path: ");
        scanf("%s", path);

        // Check if the path is absolute
        if (path[0] != '/') 
            printf("Error: Path must be absolute.\n");
        else
            break;
    }

    // Prompt user for password input
    printf("Enter password: ");
    scanf("%64s", password);

    // Call the system call with path, password, mod and recursive
    long ret = syscall(174,&path,&password,0,0);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }
    printf("---------------------------- \n");
}

// Function to execute sys_configure_path system call in add recursive mode
void execute_sys_configure_path_add_recursive() {
    char path[PATH_MAX]; // Buffer for path
    char password[65]; // Buffer for password

    while(1){
        // Prompt user for path input
        printf("Enter path: ");
        scanf("%s", path);

        // Check if the path is absolute
        if (path[0] != '/') 
            printf("Error: Path must be absolute.\n");
        else
            break;
    }

    // Prompt user for password input
    printf("Enter password: ");
    scanf("%64s", password);

    // Call the system call with path, password, mod and recursive
    long ret = syscall(174,&path,&password,0,1);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }
    printf("---------------------------- \n");
}

// Function to execute sys_configure_path system call in rmv mode
void execute_sys_configure_path_remove() {
    char path[PATH_MAX]; // Buffer for path
    char password[65]; // Buffer for password

    while(1){
        // Prompt user for path input
        printf("Enter path: ");
        scanf("%s", path);

        // Check if the path is absolute
        if (path[0] != '/') 
            printf("Error: Path must be absolute.\n");
        else
            break;
    }

    // Prompt user for password input
    printf("Enter password: ");
    scanf("%64s", password);

    // Call the system call with path, password, and mod
    long ret = syscall(174,&path,&password,1);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }
    printf("---------------------------- \n");

}

// Function to execute sys_remove_all_paths system call
void execute_sys_remove_all_paths() {
    char password[65]; // Buffer for password

    // Prompt user for password input
    printf("Enter password: ");
    scanf("%64s", password); // Limit input to 64 characters to prevent buffer overflow

    // Call the system call with password
    long ret = syscall(183,&password);

    // Check the return value of the system call
    if (ret == 0) {
        printf("System call executed successfully.\n");
    } else {
        printf("Failed to execute system call.\n");
    }

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
    system("cat ../singlefile-FS/mount/the-log");
    printf("---------------------------- \n");
}

void get_state(char * state){
    syscall(214,state);
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
    char* current_state = (char *) malloc(16 * sizeof(char));

    while (1) {
        system("clear");
        get_state(current_state);
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

    return 0;
}
