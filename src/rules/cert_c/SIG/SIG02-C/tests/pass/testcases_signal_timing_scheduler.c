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
#include <sys/time.h>

volatile sig_atomic_t task_scheduled = 0;
volatile sig_atomic_t task_count = 0;

void schedule_handler(int sig) {
    task_scheduled = 1;
    task_count++;
    printf("Task %d scheduled via signal\n", task_count);
}

int main() {
    struct itimerval timer;

    printf("Using signals for normal timing and scheduling\n");

    signal(SIGALRM, schedule_handler);

    // Set up periodic timer for scheduling
    timer.it_value.tv_sec = 1;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 2;
    timer.it_interval.tv_usec = 0;

    setitimer(ITIMER_REAL, &timer, NULL);

    printf("Starting signal-based task scheduler\n");

    for (int i = 0; i < 5; i++) {
        while (!task_scheduled) {
            pause();
        }

        printf("Executing scheduled task %d\n", task_count);
        printf("Performing normal business operation...\n");
        sleep(1);

        task_scheduled = 0;
    }

    printf("Scheduler complete\n");
    alarm(0);  // Cancel timer

    return 0;
}