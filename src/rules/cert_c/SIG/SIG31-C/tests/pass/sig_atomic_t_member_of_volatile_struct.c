/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: PASS - a sig_atomic_t member of a volatile struct object is volatile, as the object's qualifier carries to its members
 */

#include <signal.h>

static volatile struct {
    sig_atomic_t f;
} st;

typedef volatile struct {
    sig_atomic_t stop;
} control_t;
static control_t control;

static void on_term(int sig) {
    (void)sig;
    st.f = 1;
    (st).f = 1;
    control.stop = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    return 0;
}
