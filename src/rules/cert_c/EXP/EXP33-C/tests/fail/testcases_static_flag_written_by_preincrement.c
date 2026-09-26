/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - debug is static but ++debug writes it, so it is no constant 0
 * and the branch reading x uninitialized runs
 */

static int debug = 0;
void enable(void) { ++debug; }
int use(int v);
int f(void) {
    int x;
    if (debug)
        return use(x);
    return 0;
}
