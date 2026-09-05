/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL - Should trigger ARR30-C violation
 * Reason: `while (*p == K) p++;` continues while the pointee EQUALS K, so the
 *         terminator stops it for every K except the terminator itself. With
 *         0x00 written in hex this used to read as a definitely-non-NUL
 *         constant and the walk was wrongly treated as bounded.
 */

int skip_zeros(const unsigned char *p) {
    int n = 0;
    while (*p == 0x00) {
        n += *p;
        p++;
    }
    return n;
}
