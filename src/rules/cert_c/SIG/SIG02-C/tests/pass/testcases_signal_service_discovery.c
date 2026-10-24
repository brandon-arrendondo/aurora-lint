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

volatile sig_atomic_t service_register = 0;
volatile sig_atomic_t service_deregister = 0;
volatile sig_atomic_t service_health_check = 0;
volatile sig_atomic_t service_discovery = 0;

typedef struct {
    char service_name[64];
    char host[32];
    int port;
    int healthy;
} service_info_t;

service_info_t services[10];
int service_count = 0;

void discovery_handler(int sig) {
    if (sig == SIGUSR1) {
        service_register = 1;
        printf("Service registration signal received\n");
    } else if (sig == SIGUSR2) {
        service_deregister = 1;
        printf("Service deregistration signal received\n");
    } else if (sig == SIGTERM) {
        service_health_check = 1;
        printf("Service health check signal received\n");
    } else if (sig == SIGALRM) {
        service_discovery = 1;
        printf("Service discovery request signal received\n");
    }
}

int main() {
    printf("Using signals for normal service discovery operations\n");

    signal(SIGUSR1, discovery_handler);
    signal(SIGUSR2, discovery_handler);
    signal(SIGTERM, discovery_handler);
    signal(SIGALRM, discovery_handler);

    pid_t service_node = fork();
    if (service_node == 0) {
        printf("Service Node: Starting service lifecycle\n");

        sleep(1);
        printf("Service Node: Registering service\n");
        kill(getppid(), SIGUSR1);

        sleep(3);
        printf("Service Node: Requesting health check\n");
        kill(getppid(), SIGTERM);

        sleep(2);
        printf("Service Node: Discovery request\n");
        kill(getppid(), SIGALRM);

        sleep(1);
        printf("Service Node: Deregistering service\n");
        kill(getppid(), SIGUSR2);

        exit(0);
    } else {
        printf("Service Registry: Starting discovery service\n");
        int discovery_operations = 0;

        while (discovery_operations < 4) {
            pause();

            if (service_register) {
                if (service_count < 10) {
                    strcpy(services[service_count].service_name, "web-service");
                    strcpy(services[service_count].host, "192.168.1.100");
                    services[service_count].port = 8080;
                    services[service_count].healthy = 1;
                    service_count++;
                    printf("Service Registry: Registered service '%s' at %s:%d\n",
                           services[service_count-1].service_name,
                           services[service_count-1].host,
                           services[service_count-1].port);
                }
                service_register = 0;
                discovery_operations++;
            }

            if (service_health_check) {
                printf("Service Registry: Performing health check on all services\n");
                for (int i = 0; i < service_count; i++) {
                    printf("Service Registry: Health check - %s is %s\n",
                           services[i].service_name,
                           services[i].healthy ? "healthy" : "unhealthy");
                }
                service_health_check = 0;
                discovery_operations++;
            }

            if (service_discovery) {
                printf("Service Registry: Processing service discovery request\n");
                printf("Service Registry: Available services:\n");
                for (int i = 0; i < service_count; i++) {
                    printf("  - %s at %s:%d (status: %s)\n",
                           services[i].service_name, services[i].host, services[i].port,
                           services[i].healthy ? "healthy" : "unhealthy");
                }
                service_discovery = 0;
                discovery_operations++;
            }

            if (service_deregister) {
                if (service_count > 0) {
                    service_count--;
                    printf("Service Registry: Deregistered service '%s'\n",
                           services[service_count].service_name);
                }
                service_deregister = 0;
                discovery_operations++;
            }
        }

        wait(NULL);
        printf("Service discovery operations complete\n");
    }

    return 0;
}