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

volatile sig_atomic_t session_start = 0;
volatile sig_atomic_t session_end = 0;
volatile sig_atomic_t session_timeout = 0;
volatile sig_atomic_t active_sessions = 0;

typedef struct {
    int session_id;
    char username[32];
    time_t start_time;
} session_info_t;

session_info_t current_session;

void session_handler(int sig) {
    if (sig == SIGUSR1) {
        session_start = 1;
        active_sessions++;
        printf("Session start signal received (active: %d)\n", active_sessions);
    } else if (sig == SIGUSR2) {
        session_end = 1;
        if (active_sessions > 0) active_sessions--;
        printf("Session end signal received (active: %d)\n", active_sessions);
    } else if (sig == SIGALRM) {
        session_timeout = 1;
        printf("Session timeout signal received\n");
    }
}

int main() {
    printf("Using signals for normal session management (BAD)\n");

    signal(SIGUSR1, session_handler);
    signal(SIGUSR2, session_handler);
    signal(SIGALRM, session_handler);

    pid_t user_simulator = fork();
    if (user_simulator == 0) {
        printf("User Simulator: Simulating user sessions\n");

        sleep(1);
        printf("User Simulator: User login - creating session\n");
        kill(getppid(), SIGUSR1);

        sleep(5);
        printf("User Simulator: User timeout\n");
        kill(getppid(), SIGALRM);

        sleep(2);
        printf("User Simulator: User logout - ending session\n");
        kill(getppid(), SIGUSR2);

        exit(0);
    } else {
        printf("Session Manager: Starting session management service\n");
        int session_events = 0;

        while (session_events < 3) {
            pause();

            if (session_start) {
                current_session.session_id = 12345;
                strcpy(current_session.username, "john_doe");
                current_session.start_time = time(NULL);
                printf("Session Manager: Created session %d for user %s\n",
                       current_session.session_id, current_session.username);
                printf("Session Manager: Allocating resources for session\n");
                session_start = 0;
                session_events++;
            }

            if (session_timeout) {
                printf("Session Manager: Session %d timed out after inactivity\n",
                       current_session.session_id);
                printf("Session Manager: Cleaning up session resources\n");
                session_timeout = 0;
                session_events++;
            }

            if (session_end) {
                printf("Session Manager: Ending session %d for user %s\n",
                       current_session.session_id, current_session.username);
                printf("Session Manager: Saving session data and releasing resources\n");
                session_end = 0;
                session_events++;
            }
        }

        wait(NULL);
        printf("Session management complete\n");
    }

    return 0;
}