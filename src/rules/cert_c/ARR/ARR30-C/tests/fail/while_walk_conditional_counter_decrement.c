/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL - Should trigger ARR30-C violation
 * Reason: Two counter shapes that look like a bound and are not. In
 *         skip_conditionally() the decrement sits inside an `if`, so an
 *         iteration can advance the pointer without decreasing the counter.
 *         In drain_by_chunk() the counter falls by a variable amount, which
 *         terminates only if that amount is positive -- and the pointer
 *         advances by that same unknown quantity.
 */

int skip_conditionally(const unsigned char *p, unsigned left, unsigned char skip) {
    int n = 0;
    while (left) {
        if (*p == skip) {
            left--;
        }
        n += *p;
        p++;
    }
    return n;
}

int drain_by_chunk(const unsigned char *rpos, unsigned left, unsigned chunk) {
    int n = 0;
    while (left) {
        n += *rpos;
        rpos++;
        left -= chunk;
    }
    return n;
}
