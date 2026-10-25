/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a typedef of sig_atomic_t adds no volatile, and the object is declared without one
 */

#include <signal.h>

typedef sig_atomic_t flag_t;

static flag_t stop;

static void on_term(int sig) {
    (void)sig;
    stop = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    return stop;
}
