/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - the handler reads a static pointer, which is neither a volatile sig_atomic_t nor atomic, to reach its flag
 */

#include <signal.h>

static volatile sig_atomic_t done;
static volatile sig_atomic_t *slot = &done;

static void on_int(int sig) {
    (void)sig;
    *slot = 1;
}

int main(void) {
    if (signal(SIGINT, on_int) == SIG_ERR) {
        return 1;
    }
    return done;
}
