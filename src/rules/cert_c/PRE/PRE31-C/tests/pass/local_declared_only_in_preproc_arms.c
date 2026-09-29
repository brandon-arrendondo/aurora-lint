/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: n and t0 are declared only inside #if arms, and nothing outside
 * the arms declares either name. A configuration without the arm would not
 * compile, so wherever the write compiles it writes the function's own
 * automatic local. Neither function has a side effect.
 */

#define TWICE(x) ((x) + (x))

int both_arms(void) {
#ifdef _WIN32
    long n;
#else
    int n;
#endif
    n = 0;
    return (int)n;
}

int timed(int k) {
#ifdef DEBUG
    int t0;
#endif
    k *= 2;
#ifdef DEBUG
    t0 = 1;
    (void)t0;
#endif
    return k;
}

int u1(void) {
    return TWICE(both_arms());
}

int u2(int k) {
    return TWICE(timed(k));
}
