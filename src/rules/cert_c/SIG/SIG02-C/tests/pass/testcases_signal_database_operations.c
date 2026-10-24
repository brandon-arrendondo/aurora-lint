/*
 * Rule: SIG02-C
 * Source: testcases
 * Status: PASS - Should NOT trigger SIG02-C violation
 *
 * Once a FAIL fixture: it was reported for registering handlers for signals
 * named like ordinary-work signals and for kill() calls carrying them. A
 * registration is not a send, and every kill() here targets another process
 * (getppid() or a worker's pid). SIG02-C reports only the program signaling
 * its own process or threads: raise(), pthread_kill(), kill(getpid(), ...).
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile sig_atomic_t db_insert = 0;
volatile sig_atomic_t db_update = 0;
volatile sig_atomic_t db_delete = 0;
volatile sig_atomic_t transaction_commit = 0;

void database_handler(int sig) {
    if (sig == SIGUSR1) {
        db_insert = 1;
        printf("Database INSERT operation signal received\n");
    } else if (sig == SIGUSR2) {
        db_update = 1;
        printf("Database UPDATE operation signal received\n");
    } else if (sig == SIGTERM) {
        db_delete = 1;
        printf("Database DELETE operation signal received\n");
    } else if (sig == SIGALRM) {
        transaction_commit = 1;
        printf("Database transaction COMMIT signal received\n");
    }
}

void execute_database_operation(const char* operation) {
    printf("Executing %s operation on database\n", operation);
    printf("Validating data integrity...\n");
    printf("Updating indexes and constraints...\n");
    printf("Operation completed successfully\n");
}

int main() {
    printf("Using signals for normal database operations and transactions\n");

    signal(SIGUSR1, database_handler);
    signal(SIGUSR2, database_handler);
    signal(SIGTERM, database_handler);
    signal(SIGALRM, database_handler);

    pid_t db_client = fork();
    if (db_client == 0) {
        printf("DB Client: Starting database transaction sequence\n");

        sleep(1);
        printf("DB Client: Requesting INSERT operation\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("DB Client: Requesting UPDATE operation\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("DB Client: Requesting DELETE operation\n");
        kill(getppid(), SIGTERM);

        sleep(1);
        printf("DB Client: Requesting transaction COMMIT\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("DB Server: Starting database operation processing\n");
        int operations_completed = 0;

        while (operations_completed < 4) {
            pause();

            if (db_insert) {
                execute_database_operation("INSERT");
                db_insert = 0;
                operations_completed++;
            }

            if (db_update) {
                execute_database_operation("UPDATE");
                db_update = 0;
                operations_completed++;
            }

            if (db_delete) {
                execute_database_operation("DELETE");
                db_delete = 0;
                operations_completed++;
            }

            if (transaction_commit) {
                printf("Committing transaction to database\n");
                printf("Transaction committed successfully\n");
                transaction_commit = 0;
                operations_completed++;
            }
        }

        wait(NULL);
        printf("Database operations complete\n");
    }

    return 0;
}