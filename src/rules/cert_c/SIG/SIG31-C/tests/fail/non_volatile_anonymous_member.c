/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a handler writes a long member of an anonymous union inside a struct
 */

#include <signal.h>

static struct {
    int x;
    union {
        volatile sig_atomic_t f;
        long pad;
    };
} st;

static void on_term(int sig) {
    (void)sig;
    st.pad = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    return 0;
}
