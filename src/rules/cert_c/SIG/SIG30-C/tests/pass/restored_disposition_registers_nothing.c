/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: PASS - a restored disposition registers no handler; the unregistered function may call printf()
 */

#include <signal.h>
#include <stdio.h>

/* Shares its name with main()'s saved disposition. A name match would
 * register it; resolving the declaration finds the local pointer. */
static void saved(int n) {
    printf("%d\n", n);
}

int main(void) {
    void (*saved)(int) = signal(SIGINT, SIG_IGN);
    printf("working\n");
    signal(SIGINT, saved);
    return 0;
}
