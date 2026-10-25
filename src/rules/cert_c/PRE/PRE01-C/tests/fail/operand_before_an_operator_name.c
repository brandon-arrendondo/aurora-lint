/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: FAIL - an operand followed by an operator is not a type position
 *
 * An unparenthesized operand stays reported when the name after it is an
 * operator: another parameter followed by an operand (`a op b`), a macro
 * this file defines as an operator (`MOD`), or a name defined nowhere the
 * scan sees but followed by a number (`MASKED_BY 0xff`). `op` itself is
 * followed by a declarator-shaped name and is not reported.
 */

#define MOD %
#define BINOP(a, op, b) a op b
#define REMAINDER8(x) x MOD 8
#define LOW_BYTE(x) x MASKED_BY 0xff

int main(void) {
    return BINOP(1, +, 2) + REMAINDER8(10);
}
