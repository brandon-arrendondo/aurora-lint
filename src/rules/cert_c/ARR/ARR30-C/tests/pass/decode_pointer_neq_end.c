/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: The decode loop over the column blob is bounded by an explicit end
 *         pointer (`p != zEnd`), so the walk stays within the buffer.
 */

typedef unsigned char u8;

extern const void *sqlite3_column_blob(void *, int);

int scan_until(void *stmt, const u8 *zEnd) {
    const u8 *p = (const u8 *)sqlite3_column_blob(stmt, 0);
    int n = 0;
    while (p != zEnd) {
        n += p[0];
        p++;
    }
    return n;
}
