/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a struct tag defined inside a function is that block's own; the file-scope object's struct S has an int member
 */

#include <signal.h>

int probe(void) {
    struct S {
        volatile sig_atomic_t f;
    } local;
    local.f = 0;
    return local.f;
}

struct S {
    int f;
};

static struct S g;

static void on_term(int sig) {
    (void)sig;
    g.f = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    return 0;
}
