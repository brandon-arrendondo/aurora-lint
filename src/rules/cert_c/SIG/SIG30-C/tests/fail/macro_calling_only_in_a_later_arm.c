/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - a tracing macro that calls fprintf() only in its second #if arm
 */

#include <signal.h>
#include <stdio.h>

#ifndef DEBUG
#define TRACE(x) ((void)(x))
#else
#define TRACE(x) fprintf(stderr, "sig %d\n", (x))
#endif

static void on_int(int sig) {
    TRACE(sig);
}

int main(void) {
    signal(SIGINT, on_int);
    return 0;
}
