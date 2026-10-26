/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: FAIL - an operand followed by an unknown name and a number
 *
 * `MASKED_BY` is defined nowhere the scan sees. A declarator is not
 * followed by a number, so `MASKED_BY` stands between two operands as an
 * operator, and `x` is reported.
 */

#define LOW_BYTE(x) x MASKED_BY 0xff

int f(int v) {
    return LOW_BYTE(v);
}
