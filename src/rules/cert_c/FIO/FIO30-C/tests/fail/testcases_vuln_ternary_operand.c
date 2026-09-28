/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: FAIL
 * Reason: A conditional format is judged by its result operands. Here the
 *         consequence is argv[1], so the user controls the format whenever
 *         the condition holds, even though the other operand is a literal.
 */

#include <stdio.h>

int main(int argc, char *argv[]) {
    // VULNERABLE: user input selected as the format string
    printf(argc > 1 ? argv[1] : "no argument\n");
    printf((argc > 2 ? "two\n" : argv[0]));
    return 0;
}
