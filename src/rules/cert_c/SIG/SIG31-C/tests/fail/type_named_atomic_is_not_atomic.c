/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a project type whose name contains "atomic_" is a plain int, not an atomic type
 */

#include <signal.h>

typedef int atomic_counter_t;

static atomic_counter_t hits;

static void on_usr1(int sig) {
    (void)sig;
    hits++;
}

int main(void) {
    if (signal(SIGUSR1, on_usr1) == SIG_ERR) {
        return 1;
    }
    return hits;
}
