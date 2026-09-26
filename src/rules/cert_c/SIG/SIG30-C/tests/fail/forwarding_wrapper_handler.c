/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - a handler registered through a local forwarding wrapper (lua.c's setsignal shape)
 */

#include <signal.h>
#include <stdio.h>

static void laction(int i) {
    fprintf(stderr, "interrupted %d\n", i);
}

static void setsignal(int sig, void (*handler)(int)) {
    struct sigaction sa;
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

int main(void) {
    setsignal(SIGINT, laction);
    return 0;
}
