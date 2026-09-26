/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: PASS - a restored disposition registers no handler; the unregistered function may call printf()
 */

#include <signal.h>
#include <stdio.h>

static void report(int n) {
    printf("%d\n", n);
}

int main(void) {
    void (*old)(int) = signal(SIGINT, SIG_IGN);
    report(1);
    signal(SIGINT, old);
    return 0;
}
