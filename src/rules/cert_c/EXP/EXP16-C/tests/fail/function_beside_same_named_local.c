/*
 * Rule: EXP16-C
 * Source: aurora-lint
 * Status: FAIL - a function's address tested where the call was meant
 *
 * ready() tests the function count, not its result. tally() has a local
 * count, which is not the finding.
 */
int count(void);

int tally(int n) {
    int count = n;
    return count != 0;
}

int ready(void) {
    if (count)
        return 1;
    return 0;
}
