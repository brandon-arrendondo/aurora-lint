/*
 * Rule: SIG01-C
 * Source: aurora-lint
 * Status: FAIL - a wrapper installs its caller's handler with signal(); no caller in this file
 */

#include <signal.h>

void set_handler(int sig, void (*handler)(int)) {
    signal(sig, handler);
}
