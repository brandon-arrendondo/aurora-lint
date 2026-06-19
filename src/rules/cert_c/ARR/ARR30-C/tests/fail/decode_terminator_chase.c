/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL
 * Reason: Terminator-chase decode loop over a blob-derived pointer with no
 *         `p < end` bound. The blob may not contain the 0xFE marker, so the
 *         walk reads past the buffer (task 172, sqlite real-world FN family).
 */

typedef unsigned char u8;

extern const void *sqlite3_value_blob(void *);

int scan_to_marker(void *arg) {
    const u8 *p = (const u8 *)sqlite3_value_blob(arg);
    int n = 0;
    while (*p++ != 0xFE) {
        n++;
    }
    return n;
}
