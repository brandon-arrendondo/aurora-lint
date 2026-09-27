/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: PASS - an object-like alias of write() called in a handler is write()
 */

#include <signal.h>
#include <unistd.h>

#define xwrite write

static void on_term(int sig) {
    (void)sig;
    xwrite(2, "term\n", 5);
}

int main(void) {
    signal(SIGTERM, on_term);
    return 0;
}
