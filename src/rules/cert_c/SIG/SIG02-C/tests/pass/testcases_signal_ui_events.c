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

volatile sig_atomic_t button_clicked = 0;
volatile sig_atomic_t menu_selected = 0;
volatile sig_atomic_t window_resized = 0;

void button_handler(int sig) {
    button_clicked = 1;
    printf("Button click event received via signal\n");
}

void menu_handler(int sig) {
    menu_selected = 1;
    printf("Menu selection event received via signal\n");
}

void resize_handler(int sig) {
    window_resized = 1;
    printf("Window resize event received via signal\n");
}

int main() {
    printf("Using signals for normal user interface events\n");

    signal(SIGUSR1, button_handler);
    signal(SIGUSR2, menu_handler);
    signal(SIGTERM, resize_handler);

    pid_t ui_simulator = fork();
    if (ui_simulator == 0) {
        printf("UI Simulator: Generating user interface events\n");

        sleep(1);
        printf("UI Simulator: User clicked button\n");
        kill(getppid(), SIGUSR1);

        sleep(2);
        printf("UI Simulator: User selected menu item\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("UI Simulator: User resized window\n");
        kill(getppid(), SIGTERM);

        exit(0);
    } else {
        printf("Main UI: Waiting for user interface events\n");

        while (1) {
            pause();

            if (button_clicked) {
                printf("Processing button click - opening dialog\n");
                button_clicked = 0;
            }

            if (menu_selected) {
                printf("Processing menu selection - executing action\n");
                menu_selected = 0;
            }

            if (window_resized) {
                printf("Processing window resize - adjusting layout\n");
                window_resized = 0;
                break;  // Exit after handling all events
            }
        }

        wait(NULL);
        printf("UI event processing complete\n");
    }

    return 0;
}