/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - a handler writes a sig_atomic_t that is not volatile; only a volatile sig_atomic_t may be written
 */

#include <signal.h>

static sig_atomic_t flag;

static void on_int(int sig) {
    (void)sig;
    flag = 1;
}

int main(void) {
    if (signal(SIGINT, on_int) == SIG_ERR) {
        return 1;
    }
    return flag;
}
