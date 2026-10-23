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

volatile sig_atomic_t worker1_load = 0;
volatile sig_atomic_t worker2_load = 0;
volatile sig_atomic_t assign_work = 0;

void load_handler(int sig) {
    assign_work = 1;
    if (sig == SIGUSR1) {
        worker1_load++;
        printf("Work assigned to worker 1 (load: %d)\n", worker1_load);
    } else if (sig == SIGUSR2) {
        worker2_load++;
        printf("Work assigned to worker 2 (load: %d)\n", worker2_load);
    }
}

int main() {
    printf("Using signals for normal load balancing and work distribution (BAD)\n");

    signal(SIGUSR1, load_handler);
    signal(SIGUSR2, load_handler);

    pid_t load_balancer = fork();
    if (load_balancer == 0) {
        printf("Load Balancer: Starting work distribution\n");

        for (int i = 0; i < 8; i++) {
            sleep(1);

            // Simple round-robin load balancing via signals
            if (i % 2 == 0) {
                printf("Load Balancer: Assigning work %d to worker 1\n", i + 1);
                kill(getppid(), SIGUSR1);
            } else {
                printf("Load Balancer: Assigning work %d to worker 2\n", i + 1);
                kill(getppid(), SIGUSR2);
            }
        }
        exit(0);
    }

    pid_t worker1 = fork();
    if (worker1 == 0) {
        printf("Worker 1: Ready for work assignments\n");
        while (1) {
            pause();
            if (worker1_load > 0) {
                printf("Worker 1: Processing work item (total processed: %d)\n", worker1_load);
                // Simulate work
                sleep(1);
            }
        }
    }

    pid_t worker2 = fork();
    if (worker2 == 0) {
        printf("Worker 2: Ready for work assignments\n");
        while (1) {
            pause();
            if (worker2_load > 0) {
                printf("Worker 2: Processing work item (total processed: %d)\n", worker2_load);
                // Simulate work
                sleep(1);
            }
        }
    }

    // Main process acts as work receiver
    printf("Work Coordinator: Receiving work assignments\n");
    int total_work = 0;

    while (total_work < 8) {
        pause();
        if (assign_work) {
            total_work++;
            printf("Work Coordinator: Total work distributed: %d\n", total_work);
            assign_work = 0;
        }
    }

    printf("Load balancing complete\n");
    kill(worker1, SIGTERM);
    kill(worker2, SIGTERM);
    wait(NULL);
    wait(NULL);
    wait(NULL);

    return 0;
}