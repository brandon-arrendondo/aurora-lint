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

volatile sig_atomic_t event_count = 0;
volatile sig_atomic_t user_action = 0;
volatile sig_atomic_t timer_event = 0;

void user_event_handler(int sig) {
    user_action = 1;
    event_count++;
    printf("User event received (count: %d)\n", event_count);
}

void timer_event_handler(int sig) {
    timer_event = 1;
    event_count++;
    printf("Timer event received (count: %d)\n", event_count);
}

int main() {
    printf("Using signals for normal event system processing\n");

    signal(SIGUSR1, user_event_handler);
    signal(SIGUSR2, timer_event_handler);

    pid_t child = fork();
    if (child == 0) {
        // Child simulates event generation
        for (int i = 0; i < 5; i++) {
            sleep(1);
            if (i % 2 == 0) {
                printf("Child: Generating user event\n");
                kill(getppid(), SIGUSR1);
            } else {
                printf("Child: Generating timer event\n");
                kill(getppid(), SIGUSR2);
            }
        }
        exit(0);
    } else {
        // Parent processes events
        printf("Parent: Starting event processing loop\n");
        while (event_count < 5) {
            if (user_action) {
                printf("Processing user action...\n");
                user_action = 0;
            }
            if (timer_event) {
                printf("Processing timer event...\n");
                timer_event = 0;
            }
            pause();
        }
        printf("Event processing complete\n");
        wait(NULL);
    }

    return 0;
}