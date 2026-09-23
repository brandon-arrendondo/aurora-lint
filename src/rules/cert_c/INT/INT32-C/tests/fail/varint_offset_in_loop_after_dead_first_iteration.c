/*
 * Rule: INT32-C
 * Source: sqlite ext/fts3/tool/fts3view.c decodeSegment(), minimized
 * Status: FAIL - Should trigger INT32-C violation
 * Description: iPrefix and nTerm come from an untrusted on-disk varint and
 * feed memcpy's destination offset and the index store. The rule caught
 * this before an earlier fix and silently dropped it afterwards:
 *
 *   - VRA read the wrong end of `nData`'s range on the true edge of
 *     `i < nData`, claiming i <= INT_MIN-1 inside the loop -- empty against
 *     i = 0, which 1014 rightly treats as a dead edge, so the loop body
 *     was pruned on its first visit and never revived;
 *   - a dead block's successors were then computed from an empty state, so
 *     the `iPrefix = 0` arm alone reached the memcpy and VRA handed the
 *     rule a definite iPrefix = [0, 0] at a point it had already declared
 *     unreachable.
 *
 * Both the loop and the two-arm assignment are needed: drop either and the
 * finding survives on the unfixed analysis. The `iPrefix + nTerm` sum is
 * deliberately the only flaggable line, so the generated test (which asserts
 * "at least one violation") cannot pass on the strength of a neighbour.
 *
 * The flaggable line used to be the memcpy's `zTerm + iPrefix`. That is
 * pointer arithmetic on a local array -- ARR30-C's concern, not a signed
 * integer overflow -- and INT32-C only ever reported it because a local
 * ARRAY was not recognized as a pointer (an earlier fix closed that gap, the
 * same way an earlier one had for `char *`). The signed 64-bit sum of the two untrusted varints
 * is the same VRA question asked of genuine integer arithmetic.
 */

#include <string.h>

typedef long long sqlite3_int64;
int getVarint(const unsigned char *p, sqlite3_int64 *v);

void decode(const unsigned char *aData, int nData) {
    sqlite3_int64 iPrefix;
    sqlite3_int64 nTerm;
    sqlite3_int64 i = 0;
    int cnt = 0;
    char zTerm[1000];

    while (i < nData) {
        if ((cnt++) > 0) {
            i += getVarint(aData + i, &iPrefix);
        } else {
            iPrefix = 0;
        }
        i += getVarint(aData + i, &nTerm);
        /* VIOLATION: iPrefix and nTerm are unbounded varints, the sum can overflow */
        sqlite3_int64 iEnd = iPrefix + nTerm;
        memcpy(zTerm, aData + i, (size_t)nTerm);
        zTerm[iEnd] = 0;
        i += nTerm;
    }
}
