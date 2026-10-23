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

volatile sig_atomic_t step1_complete = 0;
volatile sig_atomic_t step2_complete = 0;
volatile sig_atomic_t step3_complete = 0;
volatile sig_atomic_t workflow_start = 0;

void workflow_handler(int sig) {
    if (sig == SIGUSR1) {
        workflow_start = 1;
        printf("Workflow start signal received\n");
    } else if (sig == SIGUSR2) {
        step1_complete = 1;
        printf("Step 1 completion signal received\n");
    } else if (sig == SIGTERM) {
        step2_complete = 1;
        printf("Step 2 completion signal received\n");
    } else if (sig == SIGALRM) {
        step3_complete = 1;
        printf("Step 3 completion signal received\n");
    }
}

int main() {
    printf("Using signals for normal workflow orchestration (BAD)\n");

    signal(SIGUSR1, workflow_handler);
    signal(SIGUSR2, workflow_handler);
    signal(SIGTERM, workflow_handler);
    signal(SIGALRM, workflow_handler);

    pid_t orchestrator = fork();
    if (orchestrator == 0) {
        printf("Orchestrator: Starting workflow execution\n");

        sleep(1);
        printf("Orchestrator: Initiating workflow\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("Orchestrator: Step 1 completed\n");
        kill(getppid(), SIGUSR2);

        sleep(2);
        printf("Orchestrator: Step 2 completed\n");
        kill(getppid(), SIGTERM);

        sleep(1);
        printf("Orchestrator: Step 3 completed\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Workflow Engine: Starting workflow management\n");
        int workflow_steps = 0;

        while (workflow_steps < 4) {
            pause();

            if (workflow_start) {
                printf("Workflow Engine: Starting business process workflow\n");
                printf("Workflow Engine: Initializing workflow context\n");
                workflow_start = 0;
                workflow_steps++;
            }

            if (step1_complete) {
                printf("Workflow Engine: Processing step 1 completion\n");
                printf("Workflow Engine: Data validation completed\n");
                printf("Workflow Engine: Proceeding to step 2\n");
                step1_complete = 0;
                workflow_steps++;
            }

            if (step2_complete) {
                printf("Workflow Engine: Processing step 2 completion\n");
                printf("Workflow Engine: Business logic execution completed\n");
                printf("Workflow Engine: Proceeding to step 3\n");
                step2_complete = 0;
                workflow_steps++;
            }

            if (step3_complete) {
                printf("Workflow Engine: Processing step 3 completion\n");
                printf("Workflow Engine: Final output generation completed\n");
                printf("Workflow Engine: Workflow successfully completed\n");
                step3_complete = 0;
                workflow_steps++;
            }
        }

        wait(NULL);
        printf("Workflow orchestration complete\n");
    }

    return 0;
}