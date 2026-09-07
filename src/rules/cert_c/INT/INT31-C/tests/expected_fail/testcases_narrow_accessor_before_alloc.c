/*
 * Rule: INT31-C
 * Source: testcases
 * Status: EXPECTED FAIL - a narrowing shape neither the caller-based provenance
 * work nor the value-based definite-truncation channel reaches: the converted
 * value's range is not compile-time known here, and the operand is not a
 * parameter whose callers the gate can judge. Genuine violation; kept as
 * tracked evidence of the gap.
 */

/*
 * Reason: sqlite3_value_int() returns a 32-bit int even though the
 * underlying value may need the full 64-bit range that
 * sqlite3_value_int64() preserves. Real example: sqlite
 * ext/misc/sqlar.c's sqlarUncompressFunc() reads an attacker-controlled
 * archive-entry size via sqlite3_value_int() and passes the truncated
 * result straight to sqlite3_malloc() (task 174).
 */

typedef long long sqlite3_int64;
typedef struct sqlite3_value sqlite3_value;
extern int sqlite3_value_int(sqlite3_value *v);
extern void *sqlite3_malloc(int n);

void sqlarUncompressFunc(sqlite3_value **argv)
{
    sqlite3_int64 sz;
    void *pOut;

    sz = sqlite3_value_int(argv[1]);
    pOut = sqlite3_malloc(sz);
    (void)pOut;
}
