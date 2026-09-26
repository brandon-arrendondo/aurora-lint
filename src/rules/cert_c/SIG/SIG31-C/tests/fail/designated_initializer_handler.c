/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a handler registered by a designated initializer writes a non-volatile global
 */

#include <signal.h>

static int interrupted;

static void on_int(int sig) {
    (void)sig;
    interrupted = 1;
}

int main(void) {
    struct sigaction sa = { .sa_handler = on_int };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    return interrupted;
}
