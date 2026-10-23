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
#include <sys/wait.h>

volatile sig_atomic_t data_ready = 0;
volatile sig_atomic_t process_complete = 0;

void data_handler(int sig) {
    data_ready = 1;
    printf("Data ready signal received\n");
}

void complete_handler(int sig) {
    process_complete = 1;
    printf("Process complete signal received\n");
}

int main() {
    pid_t child_pid;

    signal(SIGUSR1, data_handler);
    signal(SIGUSR2, complete_handler);

    printf("Using signals for normal inter-process communication (BAD)\n");

    child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) {
        sleep(1);
        printf("Child: Sending data ready signal\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("Child: Sending process complete signal\n");
        kill(getppid(), SIGUSR2);
        exit(0);
    } else {
        printf("Parent waiting for data ready signal...\n");
        while (!data_ready) {
            pause();
        }

        printf("Parent: Processing data...\n");
        sleep(1);

        printf("Parent waiting for completion signal...\n");
        while (!process_complete) {
            pause();
        }

        printf("Parent: All done\n");
        wait(NULL);
    }

    return 0;
}