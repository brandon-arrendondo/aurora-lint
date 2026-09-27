/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: a GNU statement expression in an unrelated function says nothing
 * about MAX or TWICE, which evaluate their arguments twice.
 */

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define TWICE(x) ((x) + (x))

int f(int i) {
    int m = MAX(i++, 3);   // VIOLATION
    int t = TWICE(i++);    // VIOLATION
    return m + t;
}

int g(void) {
    int r = ({ int i2 = 0; i2++; i2; });
    return r;
}
