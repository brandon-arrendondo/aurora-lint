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

volatile sig_atomic_t collect_metrics = 0;
volatile sig_atomic_t report_metrics = 0;
volatile sig_atomic_t reset_counters = 0;
volatile sig_atomic_t export_data = 0;

typedef struct {
    int requests_processed;
    int errors_encountered;
    double response_time_avg;
    int active_connections;
} metrics_data_t;

metrics_data_t system_metrics = {0, 0, 0.0, 0};

void metrics_handler(int sig) {
    if (sig == SIGUSR1) {
        collect_metrics = 1;
        printf("Metrics collection signal received\n");
    } else if (sig == SIGUSR2) {
        report_metrics = 1;
        printf("Metrics reporting signal received\n");
    } else if (sig == SIGTERM) {
        reset_counters = 1;
        printf("Reset counters signal received\n");
    } else if (sig == SIGALRM) {
        export_data = 1;
        printf("Export data signal received\n");
    }
}

int main() {
    printf("Using signals for normal metrics collection and reporting (BAD)\n");

    signal(SIGUSR1, metrics_handler);
    signal(SIGUSR2, metrics_handler);
    signal(SIGTERM, metrics_handler);
    signal(SIGALRM, metrics_handler);

    pid_t metrics_collector = fork();
    if (metrics_collector == 0) {
        printf("Metrics Collector: Starting metrics gathering\n");

        sleep(1);
        printf("Metrics Collector: Triggering metrics collection\n");
        kill(getppid(), SIGUSR1);

        sleep(3);
        printf("Metrics Collector: Requesting metrics report\n");
        kill(getppid(), SIGUSR2);

        sleep(2);
        printf("Metrics Collector: Exporting metrics data\n");
        kill(getppid(), SIGALRM);

        sleep(1);
        printf("Metrics Collector: Resetting counters\n");
        kill(getppid(), SIGTERM);

        exit(0);
    } else {
        printf("Metrics Service: Starting metrics processing service\n");
        int metrics_operations = 0;

        while (metrics_operations < 4) {
            pause();

            if (collect_metrics) {
                printf("Metrics Service: Collecting system metrics\n");
                system_metrics.requests_processed = 1247;
                system_metrics.errors_encountered = 23;
                system_metrics.response_time_avg = 156.7;
                system_metrics.active_connections = 45;
                printf("Metrics Service: Gathered %d requests, %d errors, %.1fms avg response\n",
                       system_metrics.requests_processed, system_metrics.errors_encountered,
                       system_metrics.response_time_avg);
                collect_metrics = 0;
                metrics_operations++;
            }

            if (report_metrics) {
                printf("Metrics Service: Generating metrics report\n");
                printf("=== System Metrics Report ===\n");
                printf("Requests Processed: %d\n", system_metrics.requests_processed);
                printf("Errors Encountered: %d\n", system_metrics.errors_encountered);
                printf("Average Response Time: %.1f ms\n", system_metrics.response_time_avg);
                printf("Active Connections: %d\n", system_metrics.active_connections);
                printf("Error Rate: %.2f%%\n",
                       (float)system_metrics.errors_encountered / system_metrics.requests_processed * 100);
                report_metrics = 0;
                metrics_operations++;
            }

            if (export_data) {
                printf("Metrics Service: Exporting metrics data to monitoring system\n");
                printf("Metrics Service: Sending data to external dashboard\n");
                printf("Metrics Service: Updating time-series database\n");
                export_data = 0;
                metrics_operations++;
            }

            if (reset_counters) {
                printf("Metrics Service: Resetting all metric counters\n");
                system_metrics.requests_processed = 0;
                system_metrics.errors_encountered = 0;
                system_metrics.response_time_avg = 0.0;
                system_metrics.active_connections = 0;
                printf("Metrics Service: Counters reset for next collection period\n");
                reset_counters = 0;
                metrics_operations++;
            }
        }

        wait(NULL);
        printf("Metrics collection and reporting complete\n");
    }

    return 0;
}