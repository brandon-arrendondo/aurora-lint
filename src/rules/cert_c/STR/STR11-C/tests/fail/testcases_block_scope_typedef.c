/*
 * Rule: STR11-C
 * Source: testcases
 * Status: FAIL - Should trigger STR11-C violation
 *
 * A block-scope typedef hides the file-scope one of the same name: the
 * array below has bound 8, so "abcdefgh" fits exactly with no terminator.
 * It must not be measured against the file-scope T4's bound of 4.
 */
typedef char T4[4];

void f(void) {
    typedef char T4[8];
    T4 c = "abcdefgh";
    (void) c;
}
