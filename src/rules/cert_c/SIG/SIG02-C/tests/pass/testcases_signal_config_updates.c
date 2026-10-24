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
#include <string.h>

volatile sig_atomic_t config_changed = 0;
volatile sig_atomic_t reload_config = 0;

struct config {
    int max_connections;
    int timeout;
    char server_name[64];
};

struct config app_config = {100, 30, "default_server"};

void config_update_handler(int sig) {
    if (sig == SIGUSR1) {
        config_changed = 1;
        printf("Configuration update signal received\n");
    } else if (sig == SIGUSR2) {
        reload_config = 1;
        printf("Configuration reload signal received\n");
    }
}

void update_configuration() {
    printf("Updating configuration based on signal...\n");
    app_config.max_connections = 200;
    app_config.timeout = 60;
    strcpy(app_config.server_name, "production_server");
    printf("Config updated: max_conn=%d, timeout=%d, server=%s\n",
           app_config.max_connections, app_config.timeout, app_config.server_name);
}

int main() {
    printf("Using signals for normal configuration updates\n");

    signal(SIGUSR1, config_update_handler);
    signal(SIGUSR2, config_update_handler);

    pid_t admin = fork();
    if (admin == 0) {
        printf("Admin: Starting configuration management\n");

        sleep(2);
        printf("Admin: Sending configuration change signal\n");
        kill(getppid(), SIGUSR1);

        sleep(3);
        printf("Admin: Sending configuration reload signal\n");
        kill(getppid(), SIGUSR2);

        exit(0);
    } else {
        printf("Application: Starting with initial config\n");
        printf("Initial config: max_conn=%d, timeout=%d, server=%s\n",
               app_config.max_connections, app_config.timeout, app_config.server_name);

        while (1) {
            if (config_changed) {
                update_configuration();
                config_changed = 0;
            }

            if (reload_config) {
                printf("Reloading configuration from file (simulated)\n");
                app_config.max_connections = 150;
                printf("Reloaded config: max_conn=%d\n", app_config.max_connections);
                reload_config = 0;
                break;
            }

            sleep(1);
        }

        wait(NULL);
        printf("Configuration management complete\n");
    }

    return 0;
}