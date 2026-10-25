/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a handler writes the int member of an array element whose other member is volatile sig_atomic_t
 */

#include <signal.h>

static struct {
    volatile sig_atomic_t f;
    int x;
} a[2];

static void on_term(int sig) {
    a[sig & 1].x = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    return 0;
}
