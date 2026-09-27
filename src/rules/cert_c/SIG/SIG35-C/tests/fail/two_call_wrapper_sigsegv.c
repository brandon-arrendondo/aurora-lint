/*
 * Rule: SIG35-C
 * Source: aurora-lint
 * Status: FAIL - a wrapper's second registering call installs a SIGSEGV handler that returns
 */

#include <signal.h>

volatile sig_atomic_t faults;

static void on_fault(int sig) {
    (void)sig;
    faults++;
}

static void install(void (*handler)(int)) {
    signal(SIGINT, handler);
    signal(SIGSEGV, handler);
}

int main(void) {
    install(on_fault);
    return 0;
}
