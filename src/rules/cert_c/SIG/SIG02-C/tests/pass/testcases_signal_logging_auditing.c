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
#include <time.h>
#include <string.h>

volatile sig_atomic_t log_event = 0;
volatile sig_atomic_t audit_event = 0;
volatile sig_atomic_t rotate_logs = 0;
volatile sig_atomic_t flush_logs = 0;

typedef enum {
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3,
    LOG_AUDIT = 4
} log_level_t;

void logging_handler(int sig) {
    if (sig == SIGUSR1) {
        log_event = LOG_INFO;
        printf("Info logging signal received\n");
    } else if (sig == SIGUSR2) {
        log_event = LOG_WARNING;
        printf("Warning logging signal received\n");
    } else if (sig == SIGTERM) {
        audit_event = 1;
        printf("Audit event signal received\n");
    } else if (sig == SIGALRM) {
        rotate_logs = 1;
        printf("Log rotation signal received\n");
    }
}

void write_log_entry(log_level_t level, const char* message) {
    time_t now = time(NULL);
    char* timestr = ctime(&now);
    timestr[strlen(timestr) - 1] = '\0';  // Remove newline

    const char* level_str;
    switch (level) {
        case LOG_INFO: level_str = "INFO"; break;
        case LOG_WARNING: level_str = "WARNING"; break;
        case LOG_ERROR: level_str = "ERROR"; break;
        case LOG_AUDIT: level_str = "AUDIT"; break;
        default: level_str = "UNKNOWN"; break;
    }

    printf("[%s] %s: %s\n", timestr, level_str, message);
}

int main() {
    printf("Using signals for normal logging and auditing operations\n");

    signal(SIGUSR1, logging_handler);
    signal(SIGUSR2, logging_handler);
    signal(SIGTERM, logging_handler);
    signal(SIGALRM, logging_handler);

    pid_t log_generator = fork();
    if (log_generator == 0) {
        printf("Log Generator: Starting logging operations\n");

        sleep(1);
        printf("Log Generator: Generating info log\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("Log Generator: Generating warning log\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("Log Generator: Generating audit event\n");
        kill(getppid(), SIGTERM);

        sleep(1);
        printf("Log Generator: Triggering log rotation\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Logger: Starting log processing service\n");
        int logging_events = 0;

        while (logging_events < 4) {
            pause();

            if (log_event == LOG_INFO) {
                write_log_entry(LOG_INFO, "User logged in successfully");
                log_event = 0;
                logging_events++;
            } else if (log_event == LOG_WARNING) {
                write_log_entry(LOG_WARNING, "High memory usage detected");
                log_event = 0;
                logging_events++;
            }

            if (audit_event) {
                write_log_entry(LOG_AUDIT, "Security event: Failed login attempt");
                printf("Notifying security team of audit event\n");
                audit_event = 0;
                logging_events++;
            }

            if (rotate_logs) {
                printf("Rotating log files for normal maintenance\n");
                write_log_entry(LOG_INFO, "Log rotation completed");
                rotate_logs = 0;
                logging_events++;
            }
        }

        wait(NULL);
        printf("Logging and auditing operations complete\n");
    }

    return 0;
}