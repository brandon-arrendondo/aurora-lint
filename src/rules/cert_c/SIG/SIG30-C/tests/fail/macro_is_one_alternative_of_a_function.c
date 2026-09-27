/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - a name that is a real function in one #if arm and an alias of signal() in the other
 */

#include <signal.h>

#if defined(USE_POSIX)
static void setsignal(int sig, void (*handler)(int)) {
    struct sigaction sa;
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}
#else
#define setsignal signal
#endif

static void on_int(int sig) {
    setsignal(sig, SIG_DFL);
}

int main(void) {
    setsignal(SIGINT, on_int);
    return 0;
}
