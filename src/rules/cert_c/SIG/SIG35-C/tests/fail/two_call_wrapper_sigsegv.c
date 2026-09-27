/*
 * Rule: SIG35-C
 * Source: aurora-lint
 * Status: FAIL - a wrapper called twice registers a SIGSEGV handler that returns
 */

#include <signal.h>

volatile sig_atomic_t faults;

static void on_int(int sig) {
    (void)sig;
}

static void on_segv(int sig) {
    (void)sig;
    faults++;
}

static void install(int sig, void (*handler)(int)) {
    signal(sig, handler);
}

int main(void) {
    install(SIGINT, on_int);
    install(SIGSEGV, on_segv);
    return 0;
}
