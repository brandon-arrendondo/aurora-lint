/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: FAIL - an operand followed by an operator macro and a plain name
 *
 * `MOD` expands to `%`, so `x` is its left operand and is reported, even
 * though the name after `MOD` is neither a number nor a parameter.
 */

#define MOD %
#define REMAINDER_Y(x) x MOD y

int main(void) {
    int y = 8;
    return REMAINDER_Y(10);
}
