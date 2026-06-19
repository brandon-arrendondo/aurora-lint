/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL
 * Reason: Varint continuation-bit chase over a column-blob pointer with no
 *         `p < end` bound. A corrupt record can set the high bit forever, so
 *         the decode reads past the blob (task 172, sqlite real-world FN family).
 */

typedef unsigned char u8;
typedef long long i64;

extern const void *sqlite3_column_blob(void *, int);

i64 read_varint(void *stmt) {
    const u8 *p = (const u8 *)sqlite3_column_blob(stmt, 0);
    i64 v = 0;
    u8 c;
    do {
        c = *p++;
        v = (v << 7) | (c & 0x7f);
    } while (c & 0x80);
    return v;
}
