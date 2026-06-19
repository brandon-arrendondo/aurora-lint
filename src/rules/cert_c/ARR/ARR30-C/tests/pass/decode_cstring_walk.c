/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: Plain NUL-terminated C-string walk. The pointer is not derived from a
 *         blob/value accessor, so the terminator is the caller's contract and
 *         the taint-gated decode-loop check must not fire (avoids the strlen FP).
 */

int my_strlen(const char *s) {
    const char *p = s;
    while (*p) {
        p++;
    }
    return (int)(p - s);
}
