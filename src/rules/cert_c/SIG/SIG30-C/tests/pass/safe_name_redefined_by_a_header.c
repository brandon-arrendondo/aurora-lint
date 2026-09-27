/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: PASS - signal() is async-safe even where a header maps it to an internal name
 */

#include <signal.h>
#include <unistd.h>

#define signal __sysv_signal

static void on_alarm(int sig) {
    signal(sig, SIG_DFL);
    alarm(1);
}

int main(void) {
    signal(SIGALRM, on_alarm);
    return 0;
}
