/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - an object-like alias of printf() called in a handler
 */

#include <signal.h>
#include <stdio.h>

#define xprintf printf

static void on_int(int sig) {
    xprintf("signal %d\n", sig);
}

int main(void) {
    signal(SIGINT, on_int);
    return 0;
}
