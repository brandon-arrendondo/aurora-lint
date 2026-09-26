/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - a handler registered only through sigaction() calls printf()
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>

static void on_usr1(int sig) {
    printf("got %d\n", sig);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    return 0;
}
