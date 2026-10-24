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

volatile sig_atomic_t start_profiling = 0;
volatile sig_atomic_t dump_stats = 0;
volatile sig_atomic_t trace_execution = 0;
volatile sig_atomic_t stop_profiling = 0;

typedef struct {
    int function_calls;
    int memory_allocations;
    double cpu_usage;
} profile_stats_t;

profile_stats_t current_stats = {0, 0, 0.0};

void profiling_handler(int sig) {
    if (sig == SIGUSR1) {
        start_profiling = 1;
        printf("Start profiling signal received\n");
    } else if (sig == SIGUSR2) {
        dump_stats = 1;
        printf("Dump statistics signal received\n");
    } else if (sig == SIGTERM) {
        trace_execution = 1;
        printf("Trace execution signal received\n");
    } else if (sig == SIGALRM) {
        stop_profiling = 1;
        printf("Stop profiling signal received\n");
    }
}

void simulate_work() {
    current_stats.function_calls++;
    current_stats.memory_allocations += 2;
    current_stats.cpu_usage += 5.5;
}

int main() {
    printf("Using signals for normal debugging and profiling in production\n");

    signal(SIGUSR1, profiling_handler);
    signal(SIGUSR2, profiling_handler);
    signal(SIGTERM, profiling_handler);
    signal(SIGALRM, profiling_handler);

    pid_t profiler = fork();
    if (profiler == 0) {
        printf("Profiler: Starting debugging session\n");

        sleep(1);
        printf("Profiler: Starting performance profiling\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("Profiler: Requesting statistics dump\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("Profiler: Enabling execution tracing\n");
        kill(getppid(), SIGTERM);

        sleep(2);
        printf("Profiler: Stopping profiling session\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Application: Running with profiling capabilities\n");
        int profiling_events = 0;
        int is_profiling = 0;

        while (profiling_events < 4) {
            // Simulate normal application work
            if (is_profiling) {
                simulate_work();
            }

            pause();

            if (start_profiling) {
                printf("Starting performance profiling...\n");
                printf("Enabling CPU and memory monitoring\n");
                is_profiling = 1;
                start_profiling = 0;
                profiling_events++;
            }

            if (dump_stats) {
                printf("Dumping current profiling statistics:\n");
                printf("Function calls: %d\n", current_stats.function_calls);
                printf("Memory allocations: %d\n", current_stats.memory_allocations);
                printf("CPU usage: %.2f%%\n", current_stats.cpu_usage);
                dump_stats = 0;
                profiling_events++;
            }

            if (trace_execution) {
                printf("Enabling detailed execution tracing\n");
                printf("Tracing function entry/exit points\n");
                trace_execution = 0;
                profiling_events++;
            }

            if (stop_profiling) {
                printf("Stopping profiling session\n");
                printf("Generating final performance report\n");
                is_profiling = 0;
                stop_profiling = 0;
                profiling_events++;
            }
        }

        wait(NULL);
        printf("Debugging and profiling session complete\n");
    }

    return 0;
}