/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: PASS - a handler writes the volatile sig_atomic_t member of an array element, and of a nested struct, also through parentheses
 */

#include <signal.h>

static struct {
    volatile sig_atomic_t f;
    int x;
} a[2];

static struct {
    long id;
    struct {
        volatile sig_atomic_t f;
    } inner;
} nested;

static void on_term(int sig) {
    a[sig & 1].f = 1;
    (a[0]).f = 1;
    nested.inner.f = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    return 0;
}
