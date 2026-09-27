/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - a logging macro in a handler expands to printf()
 */

#include <signal.h>
#include <stdio.h>

#define LOG_SIGNAL(s) printf("signal %d\n", (s))

static void on_int(int sig) {
    LOG_SIGNAL(sig);
}

int main(void) {
    signal(SIGINT, on_int);
    return 0;
}
