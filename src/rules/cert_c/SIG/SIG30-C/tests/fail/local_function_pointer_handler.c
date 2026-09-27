/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - the handler reaches signal() through a local function pointer
 */

#include <signal.h>
#include <stdio.h>

static void on_int(int sig) {
    printf("interrupted %d\n", sig);
}

int main(void) {
    void (*h)(int) = on_int;
    signal(SIGINT, h);
    return 0;
}
