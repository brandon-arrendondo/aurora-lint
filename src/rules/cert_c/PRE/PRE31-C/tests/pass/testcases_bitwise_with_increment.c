/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: CHECK_BIT's parameters `x` and `bit` are each referenced exactly
 * once, with no short-circuit/ternary branching in the body, so
 * `bit_pos++` is incremented exactly once here — identical to a plain
 * function call. There is no PRE31-C hazard without multiple (or
 * unpredictable) evaluation.
 */

#define CHECK_BIT(x, bit) (((x) & (1 << (bit))) != 0)

void check_bits(int value) {
    int bit_pos = 3;

    if (CHECK_BIT(value, bit_pos++)) {
        // bit_pos incremented exactly once - COMPLIANT
    }
}

int main(void) {
    check_bits(0x0F);
    return 0;
}
