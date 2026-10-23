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

volatile sig_atomic_t start_backup = 0;
volatile sig_atomic_t compress_data = 0;
volatile sig_atomic_t cleanup_old = 0;
volatile sig_atomic_t verify_backup = 0;

typedef struct {
    int files_backed_up;
    int compression_ratio;
    int files_cleaned;
} backup_stats_t;

backup_stats_t backup_stats = {0, 0, 0};

void maintenance_handler(int sig) {
    if (sig == SIGUSR1) {
        start_backup = 1;
        printf("Start backup signal received\n");
    } else if (sig == SIGUSR2) {
        compress_data = 1;
        printf("Data compression signal received\n");
    } else if (sig == SIGTERM) {
        cleanup_old = 1;
        printf("Cleanup old files signal received\n");
    } else if (sig == SIGALRM) {
        verify_backup = 1;
        printf("Verify backup signal received\n");
    }
}

int main() {
    printf("Using signals for normal backup and maintenance operations (BAD)\n");

    signal(SIGUSR1, maintenance_handler);
    signal(SIGUSR2, maintenance_handler);
    signal(SIGTERM, maintenance_handler);
    signal(SIGALRM, maintenance_handler);

    pid_t maintenance_scheduler = fork();
    if (maintenance_scheduler == 0) {
        printf("Maintenance Scheduler: Starting backup sequence\n");

        sleep(1);
        printf("Maintenance Scheduler: Starting backup operation\n");
        kill(getppid(), SIGUSR1);

        sleep(3);
        printf("Maintenance Scheduler: Starting compression\n");
        kill(getppid(), SIGUSR2);

        sleep(2);
        printf("Maintenance Scheduler: Cleaning up old files\n");
        kill(getppid(), SIGTERM);

        sleep(1);
        printf("Maintenance Scheduler: Verifying backup integrity\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Backup Service: Starting maintenance operations\n");
        int maintenance_tasks = 0;

        while (maintenance_tasks < 4) {
            pause();

            if (start_backup) {
                printf("Starting scheduled backup operation...\n");
                printf("Scanning files for backup...\n");
                backup_stats.files_backed_up = 1250;
                printf("Backed up %d files successfully\n", backup_stats.files_backed_up);
                start_backup = 0;
                maintenance_tasks++;
            }

            if (compress_data) {
                printf("Compressing backup data...\n");
                printf("Applying compression algorithms...\n");
                backup_stats.compression_ratio = 65;
                printf("Compression complete: %d%% space saved\n", backup_stats.compression_ratio);
                compress_data = 0;
                maintenance_tasks++;
            }

            if (cleanup_old) {
                printf("Cleaning up old backup files...\n");
                printf("Removing backups older than 30 days...\n");
                backup_stats.files_cleaned = 45;
                printf("Cleaned up %d old backup files\n", backup_stats.files_cleaned);
                cleanup_old = 0;
                maintenance_tasks++;
            }

            if (verify_backup) {
                printf("Verifying backup integrity...\n");
                printf("Checking checksums and file completeness...\n");
                printf("Backup verification successful\n");
                verify_backup = 0;
                maintenance_tasks++;
            }
        }

        wait(NULL);
        printf("Backup and maintenance operations complete\n");
        printf("Final stats: %d files backed up, %d%% compressed, %d files cleaned\n",
               backup_stats.files_backed_up, backup_stats.compression_ratio, backup_stats.files_cleaned);
    }

    return 0;
}