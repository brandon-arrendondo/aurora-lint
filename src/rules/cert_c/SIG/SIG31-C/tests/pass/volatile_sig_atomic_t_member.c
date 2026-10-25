/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: PASS - a handler writes only members whose own declared type is volatile sig_atomic_t, in an inline, a tagged and a typedef'd struct
 */

#include <signal.h>

static struct {
    volatile sig_atomic_t f;
    int x;
} st;

struct counters {
    volatile sig_atomic_t hits;
    long total;
};
static struct counters tagged;

typedef struct {
    int unused;
    volatile sig_atomic_t stop;
} control_t;
static control_t control;

static void on_term(int sig) {
    (void)sig;
    st.f = 1;
    tagged.hits = 1;
    control.stop = 1;
}

int main(void) {
    if (signal(SIGTERM, on_term) == SIG_ERR) {
        return 1;
    }
    st.x = 0;
    tagged.total = 0;
    return st.f + tagged.hits + control.stop;
}
