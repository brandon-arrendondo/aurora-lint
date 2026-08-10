/*
 * Rule: INT30-C
 * Source: task-403 regression
 * Status: FAIL - Should trigger INT30-C violation
 *
 * Guards against a same-named-variable-across-functions type leak: an
 * earlier function declares `x` as float (not an integer type), and a
 * later, unrelated function reuses the name `x` for an unsigned int used
 * in an unchecked addition. If the rule's type map is not scoped per
 * function, the whole-file map's last-write-wins semantics let one
 * function's declared type for `x` leak into the other function's lookup,
 * either wrongly suppressing the real unsigned-wrap finding below or
 * (in the reverse order) wrongly flagging the float use.
 */

void safe_use(void) {
    float x;
    x = 1.5f;
    x = x + 1.0f;
}

unsigned int risky(unsigned int x, unsigned int y) {
    unsigned int sum = x + y;  // VIOLATION: unsigned wrap, no overflow check
    return sum;
}
