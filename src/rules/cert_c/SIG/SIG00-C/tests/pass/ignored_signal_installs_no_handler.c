/*
 * Rule: SIG00-C
 * Source: aurora-lint
 * Status: PASS - ignoring a signal installs no handler, so there is nothing to mask
 */

#include <signal.h>

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    return 0;
}
