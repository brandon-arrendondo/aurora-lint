/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * `%p` prints the pointer value without reading through it, and a `%d`
 * slot's 0 is an int, so nothing here dereferences NULL.
 */
#include <stdio.h>

void show(void) {
    printf("%p %d\n", (void *)0, 0);
    printf("%p\n", NULL);
}
