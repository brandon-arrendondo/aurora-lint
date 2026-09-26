/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - OFF is defined once, unconditionally, as 0: the branch is dead
 * in every configuration
 */

#define OFF 0

int use(int v);
int f(void) {
    int x;
    if (OFF)
        return use(x);
    return 0;
}
