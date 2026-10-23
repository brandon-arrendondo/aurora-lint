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

volatile sig_atomic_t rate_limit_exceeded = 0;
volatile sig_atomic_t rate_limit_reset = 0;
volatile sig_atomic_t request_allowed = 0;
volatile sig_atomic_t request_count = 0;

void rate_limit_handler(int sig) {
    if (sig == SIGUSR1) {
        request_count++;
        if (request_count > 5) {
            rate_limit_exceeded = 1;
            printf("Rate limit exceeded signal (count: %d)\n", request_count);
        } else {
            request_allowed = 1;
            printf("Request allowed signal (count: %d)\n", request_count);
        }
    } else if (sig == SIGUSR2) {
        rate_limit_reset = 1;
        request_count = 0;
        printf("Rate limit reset signal received\n");
    }
}

int main() {
    printf("Using signals for normal rate limiting operations (BAD)\n");

    signal(SIGUSR1, rate_limit_handler);
    signal(SIGUSR2, rate_limit_handler);

    pid_t client_simulator = fork();
    if (client_simulator == 0) {
        printf("Client Simulator: Sending requests to rate limiter\n");

        for (int i = 0; i < 8; i++) {
            sleep(1);
            printf("Client Simulator: Sending request %d\n", i + 1);
            kill(getppid(), SIGUSR1);
        }

        sleep(2);
        printf("Client Simulator: Triggering rate limit reset\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("Client Simulator: Sending post-reset request\n");
        kill(getppid(), SIGUSR1);

        exit(0);
    } else {
        printf("Rate Limiter: Starting rate limiting service\n");
        int rate_events = 0;

        while (rate_events < 10) {
            pause();

            if (request_allowed) {
                printf("Rate Limiter: Request approved, processing...\n");
                printf("Rate Limiter: Current request count: %d/5\n", request_count);
                request_allowed = 0;
                rate_events++;
            }

            if (rate_limit_exceeded) {
                printf("Rate Limiter: Request rejected - rate limit exceeded\n");
                printf("Rate Limiter: Blocking request (count: %d)\n", request_count);
                printf("Rate Limiter: Client needs to wait for reset\n");
                rate_limit_exceeded = 0;
                rate_events++;
            }

            if (rate_limit_reset) {
                printf("Rate Limiter: Resetting rate limit counters\n");
                printf("Rate Limiter: Rate limit window refreshed\n");
                rate_limit_reset = 0;
                rate_events++;
            }
        }

        wait(NULL);
        printf("Rate limiting operations complete\n");
    }

    return 0;
}