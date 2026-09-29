/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * `%s` reads the string its argument points at, and the argument is the
 * null pointer constant itself, so printf() dereferences NULL.
 */
#include <stdio.h>

void greet(void) {
    printf("hello %s\n", NULL);
}
