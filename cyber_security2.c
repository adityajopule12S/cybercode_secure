#include <stdio.h>
#include <string.h>

// --- CONSTANTS ---
#define MAX_USERS 5
#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50
#define MAX_ATTEMPTS 3 // Max failed login attempts before locking
#define HASHED_PASSWORD_LEN 64 // Use a larger buffer for the simulated hash
#define MAX_FILES 5
#define MAX_THREATS 3

// --- STRUCTURE TO HOLD USER DATA ---
// NOTE: The 'password' field now stores the *hashed* version of the password.
struct User {
    char username[MAX_USERNAME_LEN];
    char hashed_password[HASHED_PASSWORD_LEN]; 
    int failed_attempts; 
    int locked;          
};

// Global variable to track the currently logged-in user (index in the array)
// -1 means no user is logged in.
int current_user_index = -1;

// Function Prototypes
void clear_input_buffer();
void initialize_users(struct User users[], int max_users);

// Hashing Function Prototype
void hash_password(const char *password, char *output_hash, size_t hash_len);

int validate_login(struct User users[], int max_users, char username[], char password[]);
void display_status(struct User users[], int max_users);
int register_user(struct User users[], int max_users, char username[], char password[]);
void unlock_account(struct User users[], int max_users, char username[]);

// --- NEW FEATURE PROTOTYPE ---
void simulate_system_scan(void);

// --- UTILITY FUNCTION TO CLEAR THE INPUT BUFFER ---
void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        // Keep reading until newline or EOF
    }
}

// --- NEW FUNCTION: SIMULATED PASSWORD HASHING ---
// In a real system, you would use cryptographically secure algorithms like 
// Argon2, bcrypt, or scrypt. This function uses a simple summation and XOR
// for *demonstration purposes only*.
void hash_password(const char *password, char *output_hash, size_t hash_len) {
    long long hash_value = 0;
    int len = strlen(password);
    
    // Simple iterative hash calculation
    for (int i = 0; i < len; i++) {
        // Combine character value with its position, using XOR for mixing
        hash_value += (password[i] ^ (i * 7));
    }
    
    // Ensure the hash stays within a reasonable range (simple modulo)
    hash_value = hash_value % 1000000000; 

    // Print the hash value into the output string buffer
    // Using a simple numeric representation of the hash for storage
    snprintf(output_hash, hash_len, "%lld", hash_value);
}

// --- FUNCTION TO INITIALIZE USER DATA ---
void initialize_users(struct User users[], int max_users) {
    char temp_hash[HASHED_PASSWORD_LEN];

    for (int i = 0; i < max_users; i++) {
        users[i].username[0] = '\0'; 
        users[i].hashed_password[0] = '\0'; 
        users[i].failed_attempts = 0;
        users[i].locked = 0;
    }

    // Initialize 'admin' user (password123)
    if (max_users > 0) {
        strcpy(users[0].username, "admin");
        hash_password("password123", temp_hash, sizeof(temp_hash));
        strcpy(users[0].hashed_password, temp_hash);
    }

    // Initialize 'user1' (mypassword)
    if (max_users > 1) {
        strcpy(users[1].username, "user1");
        hash_password("mypassword", temp_hash, sizeof(temp_hash));
        strcpy(users[1].hashed_password, temp_hash);
    }
}

// --- FUNCTION TO VALIDATE LOGIN ---
int validate_login(struct User users[], int max_users, char username[], char password[]) {
    char input_hash[HASHED_PASSWORD_LEN];
    // Hash the input password *before* comparing it to the stored hash
    hash_password(password, input_hash, sizeof(input_hash));

    for (int i = 0; i < max_users; i++) {
        // Check for an active user and matching username
        if (users[i].username[0] != '\0' && strcmp(users[i].username, username) == 0) {
            
            // 1. Account Locked Check
            if (users[i].locked) {
                printf(" Error: Account **%s** is locked.\n", username);
                return 0; 
            }
            
            // 2. Compare the HASHES
            if (strcmp(users[i].hashed_password, input_hash) == 0) {
                printf("Login successful! Welcome, **%s**.\n", username);
                users[i].failed_attempts = 0; // Reset attempts
                current_user_index = i;       // Set logged-in user
                return 1; // Success
            } else {
                // 3. Handle Incorrect Password and Locking Logic
                users[i].failed_attempts++;
                
                if (users[i].failed_attempts >= MAX_ATTEMPTS) {
                    users[i].locked = 1; // Lock the account
                    printf(" Incorrect password. Account **%s** is now **LOCKED**.\n", username);
                } else {
                    printf(" Incorrect password. **%d** attempt(s) remaining before lock.\n", MAX_ATTEMPTS - users[i].failed_attempts);
                }
                current_user_index = -1; // Ensure logged out on failure
                return 0; // Failure
            }
        }
    }
    
    // Username not found
    printf(" Username **%s** not found.\n", username);
    current_user_index = -1; // Ensure logged out
    return 0; 
}

// --- NEW FUNCTION: REGISTER A NEW USER ---
int register_user(struct User users[], int max_users, char username[], char password[]) {
    char new_user_hash[HASHED_PASSWORD_LEN];

    // 1. Check if the username already exists
    for (int i = 0; i < max_users; i++) {
        if (users[i].username[0] != '\0' && strcmp(users[i].username, username) == 0) {
            printf("Registration failed: Username **%s** already exists.\n", username);
            return 0;
        }
    }

    // 2. Find the first empty slot
    for (int i = 0; i < max_users; i++) {
        if (users[i].username[0] == '\0') { 
            // Basic length validation
            if (strlen(username) < 3 || strlen(password) < 5) {
                printf(" Registration failed: Credentials are too weak.\n");
                return 0;
            }

            // HASH the new password before storing
            hash_password(password, new_user_hash, sizeof(new_user_hash));

            strcpy(users[i].username, username);
            strcpy(users[i].hashed_password, new_user_hash);
            users[i].failed_attempts = 0;
            users[i].locked = 0;
            printf(" Registration successful! User **%s** created (Password Hashed).\n", username);
            return 1;
        }
    }

    // 3. Max limit reached
    printf(" Registration failed: Maximum user limit (**%d**) reached.\n", MAX_USERS);
    return 0;
}

// --- NEW FUNCTION: UNLOCK A LOCKED ACCOUNT ---
void unlock_account(struct User users[], int max_users, char username[]) {
    for (int i = 0; i < max_users; i++) {
        if (users[i].username[0] != '\0' && strcmp(users[i].username, username) == 0) {
            if (users[i].locked) {
                users[i].locked = 0;         
                users[i].failed_attempts = 0; 
                printf(" Account **%s** has been successfully unlocked and attempts reset.\n", username);
            } else {
                printf("ℹ Account **%s** is not currently locked.\n", username);
            }
            return;
        }
    }
    
    printf(" Username **%s** not found for unlocking.\n", username);
}

// --- NEW FEATURE: SIMULATE SYSTEM SCAN AND VIRUS CHECK ---
void simulate_system_scan(void) {
    // 1. Define simulated threat database (signatures)
    const char *threat_database[MAX_THREATS] = {
        "Trojan.Win32.Generic",
        "Keylogger.Stealer",
        "Ransomware.Lock"
    };

    // 2. Define simulated system files (one contains a signature)
    const char *system_files[MAX_FILES] = {
        "C:\\Windows\\System32\\ntkrnl.dll - Signature: 489A1B2C",
        "C:\\Users\\Guest\\Documents\\report.doc - Signature: CLEAN",
        "C:\\ProgramData\\updater.exe - Signature: A0F1E2D3 Trojan.Win32.Generic", // Infected
        "D:\\Backup\\data.zip - Signature: CLEAN",
        "C:\\temp\\file.tmp - Signature: CLEAN"
    };

    printf("\n---  Performing System Integrity and Virus Scan ---\n");
    printf("Scanning %d files against %d known threat signatures...\n", MAX_FILES, MAX_THREATS);

    int threats_found = 0;

    // 3. Simulate scanning each file
    for (int i = 0; i < MAX_FILES; i++) {
        printf("  - Scanning file: %s ... ", system_files[i]);
        
        int is_infected = 0;
        const char *found_threat = "NONE";

        // Check file content against each threat signature
        for (int j = 0; j < MAX_THREATS; j++) {
            if (strstr(system_files[i], threat_database[j]) != NULL) {
                is_infected = 1;
                found_threat = threat_database[j];
                break; // Stop searching threats for this file
            }
        }

        if (is_infected) {
            printf(" **THREAT FOUND!** [%s]\n", found_threat);
            threats_found++;
        } else {
            printf(" Clean\n");
        }
    }

    printf("\n--- Scan Summary ---\n");
    if (threats_found > 0) {
        printf(" **WARNING**: %d threat(s) found. System integrity compromised.\n", threats_found);
        printf("Action: File has been quarantined (simulated).\n");
    } else {
        printf(" **STATUS**: No threats detected. System is clean.\n");
    }
    printf("--------------------\n");
}


// --- FUNCTION TO DISPLAY USER STATUS ---
void display_status(struct User users[], int max_users) {
    printf("\n---  User Account Status (Max: %d Users) ---\n", MAX_USERS);
    printf("--------------------------------------------\n");
    for (int i = 0; i < max_users; i++) {
        if (users[i].username[0] != '\0') {
            printf("Username: **%s** | Hashed Password: **%.20s...** | Attempts: **%d** | Locked: **%s**\n",
                    users[i].username,
                    users[i].hashed_password,
                    users[i].failed_attempts,
                    users[i].locked ? " Yes" : " No");
        }
    }
    printf("--------------------------------------------\n");
}

int main(int argc, char *argv[]) {
    struct User users[MAX_USERS]; 

    initialize_users(users, MAX_USERS); 

    char username_input[MAX_USERNAME_LEN];
    char password_input[MAX_PASSWORD_LEN];
    int choice;

    printf("Welcome to the Advanced Cyber Security System Simulator.\n");
    printf("Current status: Logged in as: %s\n", current_user_index != -1 ? users[current_user_index].username : "None");

    while (1) {
        printf("\n--- Main Menu ---\n");
        // Update menu based on login state
        if (current_user_index == -1) {
            printf("1. Log in\n");
            printf("2. Register New User \n");
            printf("3. Exit\n");
        } else {
            printf("1. Log out\n"); 
            printf("2. Register New User \n");
            printf("3. Display User Status (Admin Only) 🔒\n");
            printf("4. Unlock Account (Admin Only) \n");
            printf("5. **Perform System Scan (Admin Only) **\n"); // NEW OPTION
            printf("6. Exit\n"); // Shifted to option 6
        }
        printf("Enter your choice: ");
        
        if (scanf("%d", &choice) != 1) {
            clear_input_buffer();
            printf(" Invalid choice (Non-numeric input). Please try again.\n");
            continue;
        }
        clear_input_buffer(); 

        username_input[0] = '\0';
        password_input[0] = '\0';

        if (current_user_index == -1) {
            // --- LOGGED OUT MENU OPTIONS ---
            switch (choice) {
                case 1: // Log in
                    printf("Enter username: ");
                    fgets(username_input, sizeof(username_input), stdin);
                    username_input[strcspn(username_input, "\n")] = '\0'; 

                    printf("Enter password: ");
                    fgets(password_input, sizeof(password_input), stdin);
                    password_input[strcspn(password_input, "\n")] = '\0'; 

                    validate_login(users, MAX_USERS, username_input, password_input);
                    break;

                case 2: // Register User
                    printf(" --- New User Registration ---\n");
                    printf("Enter a new username: ");
                    fgets(username_input, sizeof(username_input), stdin);
                    username_input[strcspn(username_input, "\n")] = '\0'; 

                    printf("Enter a new password: ");
                    fgets(password_input, sizeof(password_input), stdin);
                    password_input[strcspn(password_input, "\n")] = '\0';

                    register_user(users, MAX_USERS, username_input, password_input);
                    break;
                
                case 3: // Exit
                    printf(" Exiting program...\n");
                    return 0;

                default:
                    printf(" Invalid option. Please choose 1, 2, or 3.\n");
            }
        } else {
            // --- LOGGED IN MENU OPTIONS ---
            
            // Check if the current user is 'admin' (for privilege checks)
            const int is_admin = strcmp(users[current_user_index].username, "admin") == 0;

            switch (choice) {
                case 1: // Log out
                    printf(" User **%s** logged out.\n", users[current_user_index].username);
                    current_user_index = -1;
                    break;

                case 2: // Register User (Still allowed when logged in)
                    printf(" --- New User Registration ---\n");
                    printf("Enter a new username: ");
                    fgets(username_input, sizeof(username_input), stdin);
                    username_input[strcspn(username_input, "\n")] = '\0'; 

                    printf("Enter a new password: ");
                    fgets(password_input, sizeof(password_input), stdin);
                    password_input[strcspn(password_input, "\n")] = '\0';

                    register_user(users, MAX_USERS, username_input, password_input);
                    break;

                case 3: // Display Status (Admin Gate)
                    if (is_admin) {
                        display_status(users, MAX_USERS);
                    } else {
                        printf(" Access Denied. Only the **admin** user can view status.\n");
                    }
                    break;

                case 4: // Unlock Account (Admin Gate)
                    if (is_admin) {
                        printf(" --- Account Unlock/Reset (Admin) ---\n");
                        printf("Enter username to unlock: ");
                        fgets(username_input, sizeof(username_input), stdin);
                        username_input[strcspn(username_input, "\n")] = '\0'; 

                        unlock_account(users, MAX_USERS, username_input);
                    } else {
                        printf(" Access Denied. Only the **admin** user can unlock accounts.\n");
                    }
                    break;
                
                case 5: // NEW: Perform System Scan (Admin Gate)
                    if (is_admin) {
                        simulate_system_scan();
                    } else {
                        printf(" Access Denied. Only the **admin** user can run the System Scan.\n");
                    }
                    break;

                case 6: // Exit (Shifted from 5)
                    printf(" Exiting program...\n");
                    return 0;

                default:
                    printf(" Invalid option. Please choose 1, 2, 3, 4, 5, or 6.\n");
            }
        }
        printf("Current status: Logged in as: %s\n", current_user_index != -1 ? users[current_user_index].username : "None");
    }
    return 0;
}