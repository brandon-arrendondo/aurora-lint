/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * `%p` prints the pointer's value and never reads what it points at, so a
 * possibly-null getenv() result is safe there.
 */
#include <stdio.h>
#include <stdlib.h>

void show(void) {
    char *e = getenv("HOME");
    printf("%p\n", (void *)0);
    printf("%p\n", e);
}
