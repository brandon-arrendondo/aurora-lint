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

volatile sig_atomic_t message_type = 0;
volatile sig_atomic_t message_ready = 0;

typedef enum {
    MSG_NONE = 0,
    MSG_INFO = 1,
    MSG_WARNING = 2,
    MSG_STATUS = 3
} message_t;

void message_handler(int sig) {
    message_ready = 1;
    if (sig == SIGUSR1) {
        message_type = MSG_INFO;
        printf("Info message signal received\n");
    } else if (sig == SIGUSR2) {
        message_type = MSG_WARNING;
        printf("Warning message signal received\n");
    } else if (sig == SIGTERM) {
        message_type = MSG_STATUS;
        printf("Status message signal received\n");
    }
}

void process_message(message_t type) {
    switch (type) {
        case MSG_INFO:
            printf("Processing INFO message: System running normally\n");
            break;
        case MSG_WARNING:
            printf("Processing WARNING message: Resource usage high\n");
            break;
        case MSG_STATUS:
            printf("Processing STATUS message: Current status requested\n");
            break;
        default:
            printf("Unknown message type\n");
    }
}

int main() {
    printf("Using signals for normal messaging system (BAD)\n");

    signal(SIGUSR1, message_handler);
    signal(SIGUSR2, message_handler);
    signal(SIGTERM, message_handler);

    pid_t sender = fork();
    if (sender == 0) {
        printf("Sender: Starting to send regular messages\n");

        sleep(1);
        printf("Sender: Sending info message\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("Sender: Sending warning message\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("Sender: Sending status request\n");
        kill(getppid(), SIGTERM);

        exit(0);
    } else {
        printf("Receiver: Starting message processing loop\n");
        int messages_processed = 0;

        while (messages_processed < 3) {
            pause();

            if (message_ready) {
                process_message((message_t)message_type);
                messages_processed++;
                message_ready = 0;
                message_type = MSG_NONE;
            }
        }

        wait(NULL);
        printf("Message system processing complete\n");
    }

    return 0;
}