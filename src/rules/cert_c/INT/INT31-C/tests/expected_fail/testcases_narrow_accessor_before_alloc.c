/*
 * Rule: INT31-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT31-C's opt-in
 * provenance gate (converted_value_is_risky, backed by int_provenance)
 * treats that as bounded local state, so the lossy conversion is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT31-C violation and stays as
 * tracked evidence of the trade.
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
