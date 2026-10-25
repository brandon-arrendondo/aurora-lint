/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a handler writes a sig_atomic_t member of a struct object that is not volatile
 */

#include <signal.h>

static struct {
    sig_atomic_t f;
} st;

static void on_term(int sig) {
    (void)sig;
    st.f = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    return 0;
}
