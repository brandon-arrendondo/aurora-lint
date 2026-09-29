/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * The same getenv() result reaches a `%s` conversion, which reads the
 * string it points at.
 */
#include <stdio.h>
#include <stdlib.h>

void show(void) {
    char *e = getenv("HOME");
    printf("%p %s\n", e, e);
}
