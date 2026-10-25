/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: PASS - a function declared to return a pointer is called, which accesses no shared object
 */

#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t done;

static const char *farewell(void);

static void on_int(int sig) {
    (void)sig;
    (void)farewell();
    done = 1;
}

static const char *farewell(void) {
    return "bye\n";
}

int main(void) {
    if (signal(SIGINT, on_int) == SIG_ERR) {
        return 1;
    }
    return done;
}
