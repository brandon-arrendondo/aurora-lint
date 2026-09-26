/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - mode is 1 in one configuration and 0 in the other, so it has no
 * single value and the branch reading x runs in the FAST build
 */

#ifdef FAST
static const int mode = 1;
#else
static const int mode = 0;
#endif
int use(int v);
int f(void) {
    int x;
    if (mode)
        return use(x);
    return 0;
}
