/*
 * Rule: MSC13-C
 * Source: task 386 (shadow-awareness regression test)
 * Status: FAIL - the outer `x` is initialized but never read in its own
 * scope. A flat name-based read scan would wrongly count the inner block's
 * unrelated same-named `x` (which IS read) as satisfying the outer one,
 * masking this violation.
 */

#include <stdio.h>

void f(int flag) {
    int x = 1;      /* VIOLATION: outer x is never read in outer scope */
    if (flag) {
        int x = 5;  /* shadows outer x; this one IS read below */
        printf("%d\n", x);
    }
}
