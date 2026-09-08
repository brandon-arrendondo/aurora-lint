/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: FAIL
 * Reason: The counterpart to pass/testcases_paren_cursor_same_array.c. Giving
 *         a parenthesized expression the base its unparenthesized spelling
 *         would give makes the rule SEE operands it was blind to, in BOTH
 *         directions: a cursor rooted in 'first' subtracted from one rooted
 *         in 'second' is undefined, and went unreported while '(first + 4)'
 *         recorded no base at all.
 */

#include <stddef.h>

ptrdiff_t span_across_arrays(void)
{
    char first[32];
    char second[32];
    char *pos = (char *) (first + 4);
    char *tail = second + 8;

    return pos - tail;  /* VIOLATION: 'first' against 'second' */
}

int main(void)
{
    return (int) span_across_arrays();
}
