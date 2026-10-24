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

typedef enum {
    STATE_INIT,
    STATE_READY,
    STATE_PROCESSING,
    STATE_COMPLETE
} state_t;

volatile sig_atomic_t current_state = STATE_INIT;

void advance_state(int sig) {
    switch (current_state) {
        case STATE_INIT:
            current_state = STATE_READY;
            printf("State: INIT -> READY\n");
            break;
        case STATE_READY:
            current_state = STATE_PROCESSING;
            printf("State: READY -> PROCESSING\n");
            break;
        case STATE_PROCESSING:
            current_state = STATE_COMPLETE;
            printf("State: PROCESSING -> COMPLETE\n");
            break;
        case STATE_COMPLETE:
            printf("State: Already complete\n");
            break;
    }
}

int main() {
    printf("Using signals to implement state machine\n");
    printf("PID: %d\n", getpid());

    signal(SIGUSR1, advance_state);

    printf("Send SIGUSR1 to advance state machine\n");

    while (current_state != STATE_COMPLETE) {
        pause();
    }

    printf("State machine completed\n");
    return 0;
}