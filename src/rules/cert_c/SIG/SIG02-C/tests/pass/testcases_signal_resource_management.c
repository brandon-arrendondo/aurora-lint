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

volatile sig_atomic_t resource_request = 0;
volatile sig_atomic_t resource_release = 0;
volatile sig_atomic_t resource_count = 10;

void resource_handler(int sig) {
    if (sig == SIGUSR1) {
        resource_request = 1;
        printf("Resource allocation request signal received\n");
    } else if (sig == SIGUSR2) {
        resource_release = 1;
        printf("Resource deallocation signal received\n");
    }
}

void allocate_resource() {
    if (resource_count > 0) {
        resource_count--;
        printf("Resource allocated. Available: %d\n", resource_count);
    } else {
        printf("No resources available for allocation\n");
    }
}

void deallocate_resource() {
    resource_count++;
    printf("Resource deallocated. Available: %d\n", resource_count);
}

int main() {
    printf("Using signals for normal resource management\n");

    signal(SIGUSR1, resource_handler);
    signal(SIGUSR2, resource_handler);

    printf("Resource Manager: Starting with %d resources\n", resource_count);

    pid_t client1 = fork();
    if (client1 == 0) {
        printf("Client 1: Requesting resources\n");
        for (int i = 0; i < 3; i++) {
            sleep(1);
            printf("Client 1: Requesting resource %d\n", i + 1);
            kill(getppid(), SIGUSR1);
        }

        sleep(2);
        printf("Client 1: Releasing all resources\n");
        for (int i = 0; i < 3; i++) {
            kill(getppid(), SIGUSR2);
        }
        exit(0);
    }

    pid_t client2 = fork();
    if (client2 == 0) {
        sleep(4);
        printf("Client 2: Requesting resources\n");
        for (int i = 0; i < 2; i++) {
            printf("Client 2: Requesting resource %d\n", i + 1);
            kill(getppid(), SIGUSR1);
        }
        exit(0);
    }

    // Resource manager loop
    int operations = 0;
    while (operations < 8) {
        pause();

        if (resource_request) {
            allocate_resource();
            resource_request = 0;
            operations++;
        }

        if (resource_release) {
            deallocate_resource();
            resource_release = 0;
            operations++;
        }
    }

    wait(NULL);
    wait(NULL);
    printf("Resource management complete. Final available: %d\n", resource_count);

    return 0;
}