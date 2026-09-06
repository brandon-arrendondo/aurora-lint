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
 * Reason: the cast operand is an arithmetic expression ("nWord + 100"), not a
 * bare variable, so the narrowing must be caught via the dominant identifier
 * inside the expression. Real example: sqlite ext/misc/amatch.c's
 * amatchNext() -- nBuf = (char)(nWord + 100); -- both nBuf and nWord are
 * sqlite3_int64, but the (char) cast truncates through a signed byte before
 * the result is stored back and passed to a realloc call (task 174).
 */

typedef long long sqlite3_int64;
extern void *sqlite3_realloc64(void *p, sqlite3_int64 n);
extern int externally_controlled_length(void);

void amatchNext(void)
{
    sqlite3_int64 nWord;
    char *zBuf = 0;
    sqlite3_int64 nBuf = 0;

    nWord = externally_controlled_length();
    if (nWord + 20 > nBuf) {
        nBuf = (char)(nWord + 100);
        zBuf = sqlite3_realloc64(zBuf, nBuf);
    }
}
