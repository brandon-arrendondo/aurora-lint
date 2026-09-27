/*
 * Rule: SIG35-C
 * Source: aurora-lint
 * Status: PASS - one struct sigaction is reused; the handler that returns is registered only for SIGTERM, and the SIGSEGV handler aborts
 */

#include <signal.h>
#include <stdlib.h>

static void on_term(int s) { (void)s; }
static void on_segv(int s) { (void)s; abort(); }

int main(void) {
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = on_segv;
    sigaction(SIGSEGV, &sa, NULL);
    return 0;
}
