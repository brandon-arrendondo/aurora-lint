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

volatile sig_atomic_t job_scheduled = 0;
volatile sig_atomic_t job_execute = 0;
volatile sig_atomic_t job_complete = 0;
volatile sig_atomic_t schedule_next = 0;

typedef struct {
    int job_id;
    time_t scheduled_time;
    char job_name[64];
} job_info_t;

job_info_t current_job;
int next_job_id = 1;

void scheduler_handler(int sig) {
    if (sig == SIGUSR1) {
        job_scheduled = 1;
        printf("Job scheduling signal received\n");
    } else if (sig == SIGUSR2) {
        job_execute = 1;
        printf("Job execution signal received\n");
    } else if (sig == SIGTERM) {
        job_complete = 1;
        printf("Job completion signal received\n");
    } else if (sig == SIGALRM) {
        schedule_next = 1;
        printf("Schedule next job signal received\n");
    }
}

int main() {
    printf("Using signals for normal job scheduling operations (BAD)\n");

    signal(SIGUSR1, scheduler_handler);
    signal(SIGUSR2, scheduler_handler);
    signal(SIGTERM, scheduler_handler);
    signal(SIGALRM, scheduler_handler);

    pid_t job_scheduler = fork();
    if (job_scheduler == 0) {
        printf("Job Scheduler: Starting job scheduling system\n");

        sleep(1);
        printf("Job Scheduler: Scheduling first job\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("Job Scheduler: Executing scheduled job\n");
        kill(getppid(), SIGUSR2);

        sleep(3);
        printf("Job Scheduler: Job completed\n");
        kill(getppid(), SIGTERM);

        sleep(1);
        printf("Job Scheduler: Scheduling next job\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Job Engine: Starting job processing engine\n");
        int scheduling_events = 0;

        while (scheduling_events < 4) {
            pause();

            if (job_scheduled) {
                current_job.job_id = next_job_id++;
                current_job.scheduled_time = time(NULL);
                snprintf(current_job.job_name, sizeof(current_job.job_name), "daily_report_%d", current_job.job_id);
                printf("Job Engine: Scheduled job %d '%s' for execution\n",
                       current_job.job_id, current_job.job_name);
                printf("Job Engine: Adding job to execution queue\n");
                job_scheduled = 0;
                scheduling_events++;
            }

            if (job_execute) {
                printf("Job Engine: Executing job %d '%s'\n",
                       current_job.job_id, current_job.job_name);
                printf("Job Engine: Running business logic for scheduled task\n");
                printf("Job Engine: Processing data and generating reports\n");
                job_execute = 0;
                scheduling_events++;
            }

            if (job_complete) {
                printf("Job Engine: Job %d completed successfully\n", current_job.job_id);
                printf("Job Engine: Updating job status and logging results\n");
                printf("Job Engine: Freeing job resources\n");
                job_complete = 0;
                scheduling_events++;
            }

            if (schedule_next) {
                printf("Job Engine: Scheduling next recurring job\n");
                printf("Job Engine: Calculating next execution time\n");
                printf("Job Engine: Adding to future execution schedule\n");
                schedule_next = 0;
                scheduling_events++;
            }
        }

        wait(NULL);
        printf("Job scheduling operations complete\n");
    }

    return 0;
}