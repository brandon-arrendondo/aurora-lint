/*
 * Rule: MSC13-C
 * Status: FAIL - Multiple dead stores to same variable
 */

#include <stdio.h>

void f(void) {
    int x;
    x = 1;         /* VIOLATION: dead store */
    x = 2;         /* VIOLATION: dead store */
    x = 3;
    printf("%d\n", x);
}
