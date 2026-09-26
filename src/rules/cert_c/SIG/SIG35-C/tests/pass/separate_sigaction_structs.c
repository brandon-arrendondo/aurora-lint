/*
 * Rule: SIG35-C
 * Source: aurora-lint
 * Status: PASS - the SIGFPE handler never returns; the SIGTERM handler set in the same block isn't a SIGFPE handler
 */

#include <signal.h>
#include <stdlib.h>

static void on_fpe(int sig) {
    (void)sig;
    abort();
}

static void on_term(int sig) {
    (void)sig;
}

int main(void) {
    struct sigaction fpe, term;
    fpe.sa_handler = on_fpe;
    sigemptyset(&fpe.sa_mask);
    term.sa_handler = on_term;
    sigemptyset(&term.sa_mask);
    sigaction(SIGFPE, &fpe, NULL);
    sigaction(SIGTERM, &term, NULL);
    return 0;
}
