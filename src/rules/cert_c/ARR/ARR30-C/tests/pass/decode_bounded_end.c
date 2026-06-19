/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: The decode loop over the blob is bounded by an end pointer derived
 *         from the blob length, so the walk cannot read past the buffer.
 */

typedef unsigned char u8;

extern const void *sqlite3_value_blob(void *);
extern int sqlite3_value_bytes(void *);

int scan_bounded(void *arg) {
    const u8 *p = (const u8 *)sqlite3_value_blob(arg);
    const u8 *end = p + sqlite3_value_bytes(arg);
    int n = 0;
    while (p < end) {
        if (*p++ == 0xFE) {
            break;
        }
        n++;
    }
    return n;
}
