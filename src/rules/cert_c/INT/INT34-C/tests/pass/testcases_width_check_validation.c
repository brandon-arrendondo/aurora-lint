/*
 * Rule: INT34-C
 * Status: PASS - Shift amount validated with CHAR_BIT or PRECISION check
 */


#define CHAR_BIT 8

void f(int val, int n) {
    if (n >= sizeof(int) * CHAR_BIT) {
        return;
    }
    int result = val << n;  /* Safe: validated against type width */
}
