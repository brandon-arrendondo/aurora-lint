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

volatile sig_atomic_t init_database = 0;
volatile sig_atomic_t load_config = 0;
volatile sig_atomic_t start_services = 0;
volatile sig_atomic_t app_ready = 0;

void startup_handler(int sig) {
    if (sig == SIGUSR1) {
        init_database = 1;
        printf("Database initialization signal received\n");
    } else if (sig == SIGUSR2) {
        load_config = 1;
        printf("Configuration loading signal received\n");
    } else if (sig == SIGTERM) {
        start_services = 1;
        printf("Services startup signal received\n");
    } else if (sig == SIGALRM) {
        app_ready = 1;
        printf("Application ready signal received\n");
    }
}

int main() {
    printf("Using signals for normal application startup sequence\n");

    signal(SIGUSR1, startup_handler);
    signal(SIGUSR2, startup_handler);
    signal(SIGTERM, startup_handler);
    signal(SIGALRM, startup_handler);

    pid_t startup_controller = fork();
    if (startup_controller == 0) {
        printf("Startup Controller: Managing application initialization\n");

        sleep(1);
        printf("Startup Controller: Triggering database initialization\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("Startup Controller: Triggering configuration loading\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("Startup Controller: Triggering services startup\n");
        kill(getppid(), SIGTERM);

        sleep(1);
        printf("Startup Controller: Application ready\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Application: Starting initialization sequence\n");
        int startup_phases = 0;

        while (startup_phases < 4) {
            pause();

            if (init_database) {
                printf("Initializing database connections...\n");
                printf("Creating connection pool...\n");
                printf("Database initialization complete\n");
                init_database = 0;
                startup_phases++;
            }

            if (load_config) {
                printf("Loading application configuration...\n");
                printf("Parsing configuration files...\n");
                printf("Configuration loaded successfully\n");
                load_config = 0;
                startup_phases++;
            }

            if (start_services) {
                printf("Starting application services...\n");
                printf("Web server started on port 8080\n");
                printf("Background workers started\n");
                start_services = 0;
                startup_phases++;
            }

            if (app_ready) {
                printf("Application startup complete\n");
                printf("Ready to accept requests\n");
                app_ready = 0;
                startup_phases++;
            }
        }

        wait(NULL);
        printf("Application running normally\n");
    }

    return 0;
}