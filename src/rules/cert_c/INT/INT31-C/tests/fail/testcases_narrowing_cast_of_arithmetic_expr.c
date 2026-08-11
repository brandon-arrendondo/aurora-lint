/*
 * Rule: INT31-C
 * Source: testcases
 * Status: FAIL - Should trigger INT31-C violation
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
