/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: FAIL - an operand followed by a parameter used as an operator
 *
 * `a` is followed by `op`, another parameter, and then by `b`, a third: `a`
 * is the left operand of whatever operator `op` stands for, and is
 * reported. `op` sits between two operands and is the operator, which
 * parentheses would break; `b` closes the parentheses.
 */

#define BINOP(a, op, b) (a op b)

int main(void) {
    return BINOP(1, +, 2);
}
