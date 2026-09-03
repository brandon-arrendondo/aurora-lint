/*
 * Rule: MSC12-C
 * Status: FAIL - Should trigger MSC12-C violation
 * Pattern: guard already excluded by the preceding early-return guard
 *
 * Reduced from sqlite ext/fts5/fts5_index.c fts5TestUtf8() (task 612): the
 * 4-byte UTF-8 branch re-tests z[i+2] after a disjunction that already
 * returned on it, and advances i by 3 instead of 4. The duplicated
 * subcondition is the visible half of that copy-paste defect.
 */

int check_utf8_tail(const char *z, int i, int n) {
    if (i + 3 >= n || (z[i + 1] & 0xC0) != 0x80 || (z[i + 2] & 0xC0) != 0x80) {
        return 1;
    }
    if ((z[i + 2] & 0xC0) != 0x80) {  /* Noncompliant: already excluded above */
        return 1;
    }
    return 0;
}

void classify(int a, int b, int c) {
    if (a > 0 || b > 0 || c > 0)
        return;
    if (b > 0)  /* Noncompliant: reaching here means b <= 0 */
        return;
}
