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

volatile sig_atomic_t worker1_done = 0;
volatile sig_atomic_t worker2_done = 0;
volatile sig_atomic_t proceed = 0;

void worker1_handler(int sig) {
    worker1_done = 1;
    printf("Worker 1 synchronization signal received\n");
}

void worker2_handler(int sig) {
    worker2_done = 1;
    printf("Worker 2 synchronization signal received\n");
}

void proceed_handler(int sig) {
    proceed = 1;
    printf("Proceed signal received\n");
}

int main() {
    printf("Using signals for normal workflow synchronization (BAD)\n");

    signal(SIGUSR1, worker1_handler);
    signal(SIGUSR2, worker2_handler);
    signal(SIGTERM, proceed_handler);

    pid_t worker1 = fork();
    if (worker1 == 0) {
        printf("Worker 1: Starting normal work\n");
        sleep(2);
        printf("Worker 1: Work complete, signaling coordinator\n");
        kill(getppid(), SIGUSR1);

        // Wait for proceed signal
        while (!proceed) {
            pause();
        }
        printf("Worker 1: Continuing with phase 2\n");
        exit(0);
    }

    pid_t worker2 = fork();
    if (worker2 == 0) {
        printf("Worker 2: Starting normal work\n");
        sleep(3);
        printf("Worker 2: Work complete, signaling coordinator\n");
        kill(getppid(), SIGUSR2);

        // Wait for proceed signal
        while (!proceed) {
            pause();
        }
        printf("Worker 2: Continuing with phase 2\n");
        exit(0);
    }

    // Coordinator waits for both workers
    printf("Coordinator: Waiting for workers to complete phase 1\n");

    while (!worker1_done || !worker2_done) {
        pause();
    }

    printf("Coordinator: Both workers done, sending proceed signal\n");
    kill(worker1, SIGTERM);
    kill(worker2, SIGTERM);

    wait(NULL);
    wait(NULL);
    printf("All work synchronized and complete\n");

    return 0;
}