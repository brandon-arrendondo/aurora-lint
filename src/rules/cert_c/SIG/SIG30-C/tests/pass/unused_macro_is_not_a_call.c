/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: PASS - a (void)-cast macro in a handler expands to no call
 */

#include <signal.h>
#include <unistd.h>

#define UNUSED(V) ((void)V)

static void on_term(int sig) {
    UNUSED(sig);
    write(2, "term\n", 5);
}

int main(void) {
    signal(SIGTERM, on_term);
    return 0;
}
