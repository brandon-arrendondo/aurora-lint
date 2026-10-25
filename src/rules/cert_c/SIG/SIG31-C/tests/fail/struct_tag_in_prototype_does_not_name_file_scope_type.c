/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a struct tag defined in a prototype's parameter list ends with that prototype; the file-scope object's struct S has an int member
 */

#include <signal.h>

void probe(struct S { volatile sig_atomic_t f; } *p);

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
