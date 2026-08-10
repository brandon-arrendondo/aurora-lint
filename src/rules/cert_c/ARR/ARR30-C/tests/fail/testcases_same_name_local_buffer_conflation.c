/*
 * Rule: ARR30-C
 * Source: task 389
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL
 * Reason: Two different functions each declare a local buffer named "buf",
 * with different sizes. `analyze_buffer_allocations` used to build one
 * flat, whole-file HashMap<String, BufferInfo> keyed by name with no
 * function-scope boundary, so these two same-named locals conflated -
 * whichever declaration came last in the file won the map entry for both
 * functions. This function's own buffer is only 4 bytes, and the constant
 * index 50 is always out of bounds for it regardless of what a
 * differently-sized "buf" in another function looks like.
 */

void uses_small_buffer(void) {
    char buf[4];
    buf[50] = 'x';
}

void uses_large_buffer(void) {
    char buf[100];
    buf[50] = 'y';
}
