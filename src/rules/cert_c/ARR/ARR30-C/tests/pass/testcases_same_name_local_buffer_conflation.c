/*
 * Rule: ARR30-C
 * Source: task 389
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: Two different functions each declare a local buffer named "buf",
 * with different sizes, and each accesses its own buffer safely within its
 * own bounds. Before the per-function buffer scoping fix (task 389), the
 * whole-file flat buffer map could conflate these two same-named locals -
 * whichever declaration won the shared map entry could make the *other*
 * function's genuinely in-bounds access look out-of-bounds (buf[50] is
 * out-of-bounds for a 4-byte buffer, but this buf[50] is in a function
 * whose own "buf" is 100 bytes).
 */

void uses_small_buffer_safe(void) {
    char buf[4];
    buf[2] = 'x';
}

void uses_large_buffer_safe(void) {
    char buf[100];
    buf[50] = 'y';
}
