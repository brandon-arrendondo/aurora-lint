/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - TRACE is 0 only by default: a build passing -DTRACE=1 takes
 * the branch that reads x uninitialized
 */

#ifndef TRACE
#define TRACE 0
#endif

int use(int v);
int f(void) {
    int x;
    if (TRACE)
        return use(x);
    return 0;
}
