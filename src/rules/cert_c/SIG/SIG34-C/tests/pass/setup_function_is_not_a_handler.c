/*
 * Rule: SIG34-C
 * Source: aurora-lint
 * Status: PASS - a setup function with one int parameter is not a signal handler
 */

#include <signal.h>

static void on_int(int sig) {
    (void)sig;
}

void setup_signals(int verbose) {
    (void)verbose;
    signal(SIGINT, on_int);
}

int main(void) {
    setup_signals(0);
    return 0;
}
