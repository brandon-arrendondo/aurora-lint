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

volatile sig_atomic_t cpu_check = 0;
volatile sig_atomic_t memory_check = 0;
volatile sig_atomic_t disk_check = 0;
volatile sig_atomic_t network_check = 0;

typedef struct {
    int cpu_usage;
    int memory_usage;
    int disk_usage;
    int network_latency;
} health_metrics_t;

health_metrics_t current_metrics = {0, 0, 0, 0};

void health_handler(int sig) {
    if (sig == SIGUSR1) {
        cpu_check = 1;
        printf("CPU health check signal received\n");
    } else if (sig == SIGUSR2) {
        memory_check = 1;
        printf("Memory health check signal received\n");
    } else if (sig == SIGTERM) {
        disk_check = 1;
        printf("Disk health check signal received\n");
    } else if (sig == SIGALRM) {
        network_check = 1;
        printf("Network health check signal received\n");
    }
}

int main() {
    printf("Using signals for normal health monitoring operations (BAD)\n");

    signal(SIGUSR1, health_handler);
    signal(SIGUSR2, health_handler);
    signal(SIGTERM, health_handler);
    signal(SIGALRM, health_handler);

    pid_t health_monitor = fork();
    if (health_monitor == 0) {
        printf("Health Monitor: Starting system health checks\n");

        sleep(1);
        printf("Health Monitor: Triggering CPU check\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("Health Monitor: Triggering memory check\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("Health Monitor: Triggering disk check\n");
        kill(getppid(), SIGTERM);

        sleep(2);
        printf("Health Monitor: Triggering network check\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Health Service: Starting health monitoring service\n");
        int health_checks = 0;

        while (health_checks < 4) {
            pause();

            if (cpu_check) {
                printf("Health Service: Performing CPU health check\n");
                current_metrics.cpu_usage = 45;
                printf("Health Service: CPU usage at %d%%\n", current_metrics.cpu_usage);
                if (current_metrics.cpu_usage > 80) {
                    printf("Health Service: WARNING - High CPU usage detected\n");
                } else {
                    printf("Health Service: CPU health is normal\n");
                }
                cpu_check = 0;
                health_checks++;
            }

            if (memory_check) {
                printf("Health Service: Performing memory health check\n");
                current_metrics.memory_usage = 68;
                printf("Health Service: Memory usage at %d%%\n", current_metrics.memory_usage);
                if (current_metrics.memory_usage > 85) {
                    printf("Health Service: WARNING - High memory usage detected\n");
                } else {
                    printf("Health Service: Memory health is normal\n");
                }
                memory_check = 0;
                health_checks++;
            }

            if (disk_check) {
                printf("Health Service: Performing disk health check\n");
                current_metrics.disk_usage = 72;
                printf("Health Service: Disk usage at %d%%\n", current_metrics.disk_usage);
                if (current_metrics.disk_usage > 90) {
                    printf("Health Service: WARNING - High disk usage detected\n");
                } else {
                    printf("Health Service: Disk health is normal\n");
                }
                disk_check = 0;
                health_checks++;
            }

            if (network_check) {
                printf("Health Service: Performing network health check\n");
                current_metrics.network_latency = 25;
                printf("Health Service: Network latency at %dms\n", current_metrics.network_latency);
                if (current_metrics.network_latency > 100) {
                    printf("Health Service: WARNING - High network latency detected\n");
                } else {
                    printf("Health Service: Network health is normal\n");
                }
                network_check = 0;
                health_checks++;
            }
        }

        wait(NULL);
        printf("Health monitoring complete\n");
        printf("Final metrics - CPU: %d%%, Memory: %d%%, Disk: %d%%, Latency: %dms\n",
               current_metrics.cpu_usage, current_metrics.memory_usage,
               current_metrics.disk_usage, current_metrics.network_latency);
    }

    return 0;
}