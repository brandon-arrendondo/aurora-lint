/*
 * Rule: SIG01-C
 * Source: aurora-lint
 * Status: PASS - restoring a saved disposition installs no handler
 */

#include <signal.h>

int main(void) {
    void (*old)(int) = signal(SIGPIPE, SIG_IGN);
    signal(SIGPIPE, old);
    return 0;
}
