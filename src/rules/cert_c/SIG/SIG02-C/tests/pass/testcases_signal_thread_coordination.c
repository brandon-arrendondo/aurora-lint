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

volatile sig_atomic_t thread1_ready = 0;
volatile sig_atomic_t thread2_ready = 0;
volatile sig_atomic_t start_phase2 = 0;
volatile sig_atomic_t all_done = 0;

void coordination_handler(int sig) {
    if (sig == SIGUSR1) {
        thread1_ready = 1;
        printf("Thread 1 ready signal received\n");
    } else if (sig == SIGUSR2) {
        thread2_ready = 1;
        printf("Thread 2 ready signal received\n");
    } else if (sig == SIGTERM) {
        start_phase2 = 1;
        printf("Start phase 2 signal received\n");
    } else if (sig == SIGALRM) {
        all_done = 1;
        printf("All done signal received\n");
    }
}

int main() {
    printf("Using signals for normal thread coordination\n");

    signal(SIGUSR1, coordination_handler);
    signal(SIGUSR2, coordination_handler);
    signal(SIGTERM, coordination_handler);
    signal(SIGALRM, coordination_handler);

    pid_t worker1 = fork();
    if (worker1 == 0) {
        printf("Worker 1: Starting phase 1 work\n");
        sleep(2);
        printf("Worker 1: Phase 1 complete, signaling ready\n");
        kill(getppid(), SIGUSR1);

        // Wait for phase 2 signal
        while (!start_phase2) {
            pause();
        }
        printf("Worker 1: Starting phase 2 work\n");
        sleep(1);
        printf("Worker 1: All work complete\n");
        exit(0);
    }

    pid_t worker2 = fork();
    if (worker2 == 0) {
        printf("Worker 2: Starting phase 1 work\n");
        sleep(3);
        printf("Worker 2: Phase 1 complete, signaling ready\n");
        kill(getppid(), SIGUSR2);

        // Wait for phase 2 signal
        while (!start_phase2) {
            pause();
        }
        printf("Worker 2: Starting phase 2 work\n");
        sleep(2);
        printf("Worker 2: All work complete\n");
        kill(getppid(), SIGALRM);
        exit(0);
    }

    // Coordinator process
    printf("Coordinator: Managing thread coordination\n");
    int coordination_events = 0;

    while (coordination_events < 3) {
        pause();

        if (thread1_ready && !start_phase2) {
            printf("Coordinator: Worker 1 ready for phase 2\n");
        }

        if (thread2_ready && !start_phase2) {
            printf("Coordinator: Worker 2 ready for phase 2\n");
        }

        if (thread1_ready && thread2_ready && !start_phase2) {
            printf("Coordinator: Both workers ready, starting phase 2\n");
            kill(worker1, SIGTERM);
            kill(worker2, SIGTERM);
            start_phase2 = 1;
            coordination_events++;
        }

        if (all_done) {
            printf("Coordinator: All workers completed\n");
            coordination_events = 3;  // Exit loop
        }
    }

    wait(NULL);
    wait(NULL);
    printf("Thread coordination complete\n");

    return 0;
}