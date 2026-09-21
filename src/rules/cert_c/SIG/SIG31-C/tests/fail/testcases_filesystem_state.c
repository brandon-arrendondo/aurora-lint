/*
 * Rule: SIG31-C
 * Source: testcases
 * Status: FAIL - Should trigger SIG31-C violation
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>

typedef struct {
    char current_directory[512];
    char temp_directory[512];
    char log_directory[512];
    int open_files_count;
    long total_disk_space;
    long available_disk_space;
    double disk_usage_percent;
} filesystem_state_t;

typedef struct {
    char watched_paths[10][256];
    int path_count;
    time_t last_modified[10];
    int file_permissions[10];
    long file_sizes[10];
    char file_types[10][16];
} file_monitor_t;

filesystem_state_t global_fs_state = {0};
file_monitor_t global_file_monitor = {0};

void update_disk_stats(void) {
    /* Simulate disk space calculation */
    global_fs_state.total_disk_space = 1000000000;  /* 1GB */
    global_fs_state.available_disk_space = 500000000 - (rand() % 100000000);
    global_fs_state.disk_usage_percent =
        ((double)(global_fs_state.total_disk_space - global_fs_state.available_disk_space) /
         global_fs_state.total_disk_space) * 100.0;
}

void unsafe_handler(int sig) {
    /* Violation: Accessing shared file system state in signal handler */

    if (sig == SIGUSR1) {
        /* Emergency cleanup: change directories and paths */
        strcpy(global_fs_state.current_directory, "/tmp/claude/emergency");
        strcpy(global_fs_state.temp_directory, "/tmp/claude/signal_temp");
        strcpy(global_fs_state.log_directory, "/tmp/claude/signal_logs");
        global_fs_state.open_files_count += 10;
    } else if (sig == SIGUSR2) {
        /* File monitoring update */
        for (int i = 0; i < global_file_monitor.path_count; i++) {
            global_file_monitor.last_modified[i] = time(NULL);
            global_file_monitor.file_permissions[i] = 0644;
            global_file_monitor.file_sizes[i] += 1024;
            strcpy(global_file_monitor.file_types[i], "SIGNAL_MODIFIED");
        }

        /* Add new monitored path */
        if (global_file_monitor.path_count < 10) {
            sprintf(global_file_monitor.watched_paths[global_file_monitor.path_count],
                    "/tmp/claude/signal_%d.tmp", sig);
            global_file_monitor.last_modified[global_file_monitor.path_count] = time(NULL);
            global_file_monitor.file_permissions[global_file_monitor.path_count] = 0600;
            global_file_monitor.file_sizes[global_file_monitor.path_count] = 512;
            strcpy(global_file_monitor.file_types[global_file_monitor.path_count], "TEMP");
            global_file_monitor.path_count++;
        }
    }

    /* Update disk statistics in signal handler - dangerous! */
    update_disk_stats();

    printf("Handler: cwd=%s, open_files=%d, disk_usage=%.1f%%, monitored_paths=%d\n",
           global_fs_state.current_directory,
           global_fs_state.open_files_count,
           global_fs_state.disk_usage_percent,
           global_file_monitor.path_count);
}

int main() {
    printf("Demonstrating unsafe file system state access in signal handler\n");
    printf("PID: %d\n", getpid());

    /* Initialize file system state */
    strcpy(global_fs_state.current_directory, "/home/user/working/certc_cases");
    strcpy(global_fs_state.temp_directory, "/tmp/claude");
    strcpy(global_fs_state.log_directory, "/tmp/claude/logs");
    global_fs_state.open_files_count = 5;

    /* Initialize file monitor */
    global_file_monitor.path_count = 3;
    strcpy(global_file_monitor.watched_paths[0], "/tmp/claude/test1.log");
    strcpy(global_file_monitor.watched_paths[1], "/tmp/claude/test2.dat");
    strcpy(global_file_monitor.watched_paths[2], "/tmp/claude/test3.cfg");

    for (int i = 0; i < 3; i++) {
        global_file_monitor.last_modified[i] = time(NULL) - (i * 60);
        global_file_monitor.file_permissions[i] = 0644;
        global_file_monitor.file_sizes[i] = 1024 + (i * 512);
        strcpy(global_file_monitor.file_types[i], "REGULAR");
    }

    update_disk_stats();

    signal(SIGUSR1, unsafe_handler);
    signal(SIGUSR2, unsafe_handler);

    for (int i = 0; i < 25; i++) {
        /* Simulate file system operations */
        sprintf(global_fs_state.current_directory, "/home/user/working/certc_cases/iter_%d", i);
        global_fs_state.open_files_count = 5 + (i % 10);

        /* Update monitored files */
        for (int j = 0; j < global_file_monitor.path_count && j < 10; j++) {
            global_file_monitor.last_modified[j] = time(NULL);
            global_file_monitor.file_sizes[j] += 64;

            /* Simulate permission changes */
            if (i % 5 == 4) {
                global_file_monitor.file_permissions[j] = 0600;
            } else {
                global_file_monitor.file_permissions[j] = 0644;
            }
        }

        /* Update disk stats */
        update_disk_stats();

        /* Simulate adding new monitored files */
        if (i % 7 == 6 && global_file_monitor.path_count < 10) {
            sprintf(global_file_monitor.watched_paths[global_file_monitor.path_count],
                    "/tmp/claude/main_%d.tmp", i);
            global_file_monitor.last_modified[global_file_monitor.path_count] = time(NULL);
            global_file_monitor.file_permissions[global_file_monitor.path_count] = 0644;
            global_file_monitor.file_sizes[global_file_monitor.path_count] = 256;
            strcpy(global_file_monitor.file_types[global_file_monitor.path_count], "MAIN_TEMP");
            global_file_monitor.path_count++;
        }

        printf("Main: cwd=%s, open_files=%d, disk_usage=%.1f%%, monitored=%d, total_size=%ld\n",
               global_fs_state.current_directory,
               global_fs_state.open_files_count,
               global_fs_state.disk_usage_percent,
               global_file_monitor.path_count,
               global_file_monitor.path_count > 0 ? global_file_monitor.file_sizes[0] : 0);

        usleep(120000);
    }

    return 0;
}