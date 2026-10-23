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

volatile sig_atomic_t notification_pending = 0;
volatile sig_atomic_t notification_type = 0;

typedef enum {
    NOTIFY_EMAIL = 1,
    NOTIFY_SMS = 2,
    NOTIFY_PUSH = 3
} notification_type_t;

void notification_handler(int sig) {
    notification_pending = 1;
    if (sig == SIGUSR1) {
        notification_type = NOTIFY_EMAIL;
        printf("Email notification signal received\n");
    } else if (sig == SIGUSR2) {
        notification_type = NOTIFY_SMS;
        printf("SMS notification signal received\n");
    } else if (sig == SIGTERM) {
        notification_type = NOTIFY_PUSH;
        printf("Push notification signal received\n");
    }
}

void send_notification(notification_type_t type) {
    time_t now = time(NULL);
    printf("Timestamp: %s", ctime(&now));

    switch (type) {
        case NOTIFY_EMAIL:
            printf("Sending email notification: Daily report ready\n");
            break;
        case NOTIFY_SMS:
            printf("Sending SMS notification: Account balance low\n");
            break;
        case NOTIFY_PUSH:
            printf("Sending push notification: New message received\n");
            break;
        default:
            printf("Unknown notification type\n");
    }
}

int main() {
    printf("Using signals for normal notification workflow (BAD)\n");

    signal(SIGUSR1, notification_handler);
    signal(SIGUSR2, notification_handler);
    signal(SIGTERM, notification_handler);

    pid_t notifier = fork();
    if (notifier == 0) {
        printf("Notifier: Starting notification generation\n");

        sleep(2);
        printf("Notifier: Triggering email notification\n");
        kill(getppid(), SIGUSR1);

        sleep(3);
        printf("Notifier: Triggering SMS notification\n");
        kill(getppid(), SIGUSR2);

        sleep(2);
        printf("Notifier: Triggering push notification\n");
        kill(getppid(), SIGTERM);

        exit(0);
    } else {
        printf("Notification Service: Starting notification processing\n");
        int notifications_sent = 0;

        while (notifications_sent < 3) {
            pause();

            if (notification_pending) {
                send_notification((notification_type_t)notification_type);
                notifications_sent++;
                printf("Notifications sent: %d\n", notifications_sent);
                notification_pending = 0;
                notification_type = 0;
            }
        }

        wait(NULL);
        printf("Notification service processing complete\n");
    }

    return 0;
}