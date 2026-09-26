/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - the local flag shadows the file-scope constant, so the
 * condition is the value get() returns, not 0
 */

static const int flag = 0;
int get(void);
int use(int v);
int f(void) {
    int flag = get();
    int x;
    if (flag)
        return use(x);
    return 0;
}
