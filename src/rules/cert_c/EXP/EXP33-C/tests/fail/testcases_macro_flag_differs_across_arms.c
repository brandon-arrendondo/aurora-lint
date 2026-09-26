/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - MODE is 0 in the FAST build and 1 otherwise, so the branch
 * reading x runs in one configuration and is not dead
 */

#ifdef FAST
#define MODE 0
#else
#define MODE 1
#endif

int use(int v);
int f(void) {
    int x;
    if (MODE)
        return use(x);
    return 0;
}
