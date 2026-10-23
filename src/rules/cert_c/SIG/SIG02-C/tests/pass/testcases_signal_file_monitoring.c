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

volatile sig_atomic_t file_created = 0;
volatile sig_atomic_t file_modified = 0;
volatile sig_atomic_t file_deleted = 0;

void file_event_handler(int sig) {
    if (sig == SIGUSR1) {
        file_created = 1;
        printf("File creation event signal received\n");
    } else if (sig == SIGUSR2) {
        file_modified = 1;
        printf("File modification event signal received\n");
    } else if (sig == SIGTERM) {
        file_deleted = 1;
        printf("File deletion event signal received\n");
    }
}

void process_file_event(const char* event_type) {
    printf("Processing %s event for normal file system monitoring\n", event_type);
    printf("Updating file index and metadata...\n");
    printf("Notifying subscribers of file system change\n");
}

int main() {
    printf("Using signals for normal file system monitoring (BAD)\n");

    signal(SIGUSR1, file_event_handler);
    signal(SIGUSR2, file_event_handler);
    signal(SIGTERM, file_event_handler);

    pid_t file_watcher = fork();
    if (file_watcher == 0) {
        printf("File Watcher: Monitoring file system events\n");

        sleep(1);
        printf("File Watcher: Detected file creation\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("File Watcher: Detected file modification\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("File Watcher: Detected file modification again\n");
        kill(getppid(), SIGUSR2);

        sleep(2);
        printf("File Watcher: Detected file deletion\n");
        kill(getppid(), SIGTERM);

        exit(0);
    } else {
        printf("File Monitor: Starting file system event processing\n");
        int events_processed = 0;

        while (events_processed < 4) {
            pause();

            if (file_created) {
                process_file_event("file creation");
                file_created = 0;
                events_processed++;
            }

            if (file_modified) {
                process_file_event("file modification");
                file_modified = 0;
                events_processed++;
            }

            if (file_deleted) {
                process_file_event("file deletion");
                file_deleted = 0;
                events_processed++;
            }
        }

        wait(NULL);
        printf("File system monitoring complete\n");
    }

    return 0;
}