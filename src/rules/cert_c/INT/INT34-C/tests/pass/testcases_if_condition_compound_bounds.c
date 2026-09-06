/*
 * Rule: INT34-C
 * Status: PASS - Compound if condition bounds shift amount
 */


void f(int val, int shift) {
    if (shift >= 0 && shift < 32) {
        int result = val << shift;  /* Safe: shift in [0, 31] */
    }
}

void g(int val, int n) {
    if (n < 0) {
        return;  /* Error handling: negative shift */
    }
    int result = val >> n;
}
