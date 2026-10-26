/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: FAIL - an operand followed by a macro this file defines as an
 * operator
 *
 * `MOD` expands to `%`, not to a type or a string literal, so `x` is its
 * left operand and is reported.
 */

#define MOD %
#define REMAINDER8(x) x MOD 8

int main(void) {
    return REMAINDER8(10);
}
