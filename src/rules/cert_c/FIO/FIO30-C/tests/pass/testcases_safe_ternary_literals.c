/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: PASS
 * Reason: A conditional format whose two result operands are both string
 *         literals can only ever select a literal. The condition picks
 *         which one; it never reaches the format slot, even when it is
 *         derived from user input. Parentheses around the conditional
 *         do not change what it selects.
 */

#include <stdio.h>

int main(int argc, char *argv[]) {
    int verbose = argc > 1;

    printf(verbose ? "verbose: %d args\n" : "%d args\n", argc);
    printf(argc > 2 ? "many\n" : argc > 1 ? "one\n" : "none\n");
    fprintf(stderr, argv[1] ? "given: %s\n" : "missing%s\n", "");
    printf(((argc % 2) == 0) ? "even\n" : "odd\n");
    return 0;
}
