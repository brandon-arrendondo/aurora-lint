/*
 * Rule: EXP00-C
 * Source: aurora-lint
 * Status: PASS - every comparison beside a bitwise operator is already grouped
 *
 * A comparison inside parentheses or a call's argument list is evaluated as
 * written, and a bitwise operator with the constant 0 has no precedence to
 * clarify.
 */
int f(int v);

int grouped(int a, int b, int c, int x) {
    int r = a & f(b == c);
    r |= a & (b == c);
    r |= x | 0;
    r |= (a == b) & (c == x);
    return r;
}
