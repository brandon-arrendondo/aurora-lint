/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the operand of sizeof is not evaluated (C11 6.5.3.4p2), so SZ
 * evaluates x exactly once.
 */

#define SZ(x) (sizeof(x) + (x))

void q(int i) {
    int s = SZ(i++);
    (void)s;
}
