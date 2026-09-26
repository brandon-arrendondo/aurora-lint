/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: EXPECTED_FAIL - the Implicit Size form, not detected yet
 *
 * Each array's bound comes only from its brace initializer, which is the
 * construct CERT ARR02-C's "Noncompliant Code Example (Implicit Size)" names.
 * Only a character array initialized by a string literal is exempt (EX1).
 * Moved out of tests/pass/ together with that noncompliant example.
 */

#include <stdio.h>

int main() {
    int implicit_array[] = {1, 2, 3, 4, 5};
    double values[] = {1.1, 2.2, 3.3};

    printf("%d %f\n", implicit_array[0], values[0]);
    return 0;
}
