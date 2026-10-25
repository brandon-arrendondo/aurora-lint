/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: PASS - volatile sig_atomic_t objects, with the volatile on a typedef, after the type, or on the object of a plain typedef
 */

#include <signal.h>

typedef volatile sig_atomic_t vflag_t;
typedef sig_atomic_t flag_t;

static vflag_t got_int;
static sig_atomic_t volatile got_term;
static volatile flag_t got_hup;
static volatile sig_atomic_t counts[4];

static void on_signal(int sig) {
    if (sig == SIGINT) {
        got_int = 1;
    } else if (sig == SIGTERM) {
        got_term = 1;
    } else {
        got_hup = 1;
    }
    counts[0] = 1;
}

int main(void) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    return got_int + got_term + got_hup + counts[0];
}
