/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a handler writes an int member of a struct whose other member is volatile sig_atomic_t; each member is judged by its own type
 */

#include <signal.h>

static struct {
    volatile sig_atomic_t f;
    int x;
} st;

static void on_term(int sig) {
    (void)sig;
    st.x = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    return st.f + st.x;
}
