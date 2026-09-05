/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: NUL-terminated string scans. The sentinel test in the loop condition
 *         IS the bound, in every spelling: bare truthiness, an explicit
 *         comparison against '\0'/0, and a read captured by an assignment.
 *         Each body dereferences the walked pointer, which is what reaches the
 *         unbounded-pointer-increment check. Flagging these was the single
 *         largest ARR30-C false-positive source in the real-world corpus.
 */

int count_upper_truthiness(const char *s) {
    const char *p = s;
    int n = 0;
    while (*p) {
        if (*p >= 'A' && *p <= 'Z') {
            n++;
        }
        p++;
    }
    return n;
}

int count_spaces_explicit_nul(const char *s) {
    const char *p = s;
    int n = 0;
    while (*p != '\0') {
        if (*p == ' ') {
            n++;
        }
        p++;
    }
    return n;
}

int sum_bytes_zero_literal(const char *s) {
    const char *p = s;
    int sum = 0;
    while (*p != 0) {
        sum += *p;
        p++;
    }
    return sum;
}

int checksum_assigned_read(const char *s) {
    const char *p = s;
    int c;
    int sum = 0;
    while ((c = *p) != 0) {
        sum += c + *p;
        p++;
    }
    return sum;
}
