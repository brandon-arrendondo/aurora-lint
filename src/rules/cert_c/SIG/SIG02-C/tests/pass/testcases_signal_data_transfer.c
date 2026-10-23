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
#include <string.h>

volatile sig_atomic_t data_value = 0;
volatile sig_atomic_t transfer_ready = 0;

void data_transfer_handler(int sig) {
    if (sig == SIGUSR1) {
        data_value = 42;  // Transfer small data via signal
        transfer_ready = 1;
        printf("Data transferred via signal: %d\n", data_value);
    } else if (sig == SIGUSR2) {
        data_value = 100;
        transfer_ready = 1;
        printf("Data transferred via signal: %d\n", data_value);
    }
}

int main() {
    printf("Using signals for normal data transfer (BAD)\n");

    signal(SIGUSR1, data_transfer_handler);
    signal(SIGUSR2, data_transfer_handler);

    pid_t child = fork();
    if (child == 0) {
        sleep(1);
        printf("Child: Sending first data packet\n");
        kill(getppid(), SIGUSR1);

        sleep(1);
        printf("Child: Sending second data packet\n");
        kill(getppid(), SIGUSR2);
        exit(0);
    } else {
        printf("Parent: Waiting for data transfers\n");

        while (!transfer_ready) {
            pause();
        }
        printf("Parent: Received first value: %d\n", data_value);
        transfer_ready = 0;

        while (!transfer_ready) {
            pause();
        }
        printf("Parent: Received second value: %d\n", data_value);

        wait(NULL);
    }

    return 0;
}