/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: FAIL - a parameter before a keyword is not in a type name
 *
 * `x` is the statement of the `if`, followed by `else`. A keyword starts
 * no operand, so `x` is not an operator between two operands, and no type
 * name continues with `else`; `(x)` compiles, and `x` is reported.
 */

#define IF_ELSE(c, x, y) if (c) x else (y)

void f(int c, int *p) {
    IF_ELSE(c, *p = 1;, *p = 2;);
}
