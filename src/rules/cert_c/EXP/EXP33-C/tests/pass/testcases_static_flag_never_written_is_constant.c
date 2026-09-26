/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - staticFalse is static, never written and its address never
 * taken, so it is a constant 0 and the branch is dead (the Juliet
 * flow-variant idiom)
 */

static int staticFalse = 0;
int use(int v);
int f(void) {
    int x;
    if (staticFalse)
        return use(x);
    return 0;
}
