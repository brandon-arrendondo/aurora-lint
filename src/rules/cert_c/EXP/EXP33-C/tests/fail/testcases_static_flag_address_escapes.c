/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - the address of debug is handed out, so any pointer write may
 * change it: it is no constant 0 and the branch reading x runs
 */

static int debug = 0;
void reg(int *p);
void setup(void) { reg(&debug); }
int use(int v);
int f(void) {
    int x;
    if (debug)
        return use(x);
    return 0;
}
