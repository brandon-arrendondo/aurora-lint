/*
 * Rule: MSC13-C
 * Source: task 386 (shadow-awareness regression test)
 * Status: PASS - both the outer and the inner same-named `x` are read within
 * their own scopes; shadow-aware read counting must not conflate one
 * variable's read with the other's.
 */

#include <stdio.h>

void f(int flag) {
    int x = 1;
    printf("%d\n", x);
    if (flag) {
        int x = 5;
        printf("%d\n", x);
    }
}
