/*
 * Rule: SIG00-C
 * Source: aurora-lint
 * Status: FAIL - a static wrapper's signal() installs what a public forwarder's callers pass
 */

#include <signal.h>

static void set(int sig, void (*handler)(int)) {
    signal(sig, handler);
}

void install(void (*cb)(int)) {
    set(SIGINT, cb);
}
