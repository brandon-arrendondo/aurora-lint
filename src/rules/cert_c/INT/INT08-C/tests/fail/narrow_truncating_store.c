/* Rule: INT08-C
 * Source: custom (task 925)
 * Status: FAIL - SHOULD trigger INT08-C violation
 *
 * The store, not the arithmetic. `a + b` here is a correct int computation
 * -- both operands promote and 33000 fits `int` comfortably, which is why
 * task 755 moved this shape out of tests/fail -- but 33000 cannot be
 * represented in a `short`, and "verify that all integer values are in
 * range" is this rule's own title.
 *
 * Nothing else in the suite catches it: INT31-C's conversion check compares
 * DECLARED widths, so `short = short + short` is width-equal and it stays
 * silent, and INT32-C's question is about the arithmetic, which is fine here.
 *
 * Definite truncations only -- the computed range has to lie entirely outside
 * the destination's, which needs operands the range engine can resolve.
 */

void short_sum_truncates(void) {
    short a = 32000;
    short b = 1000;
    short result = a + b;      /* 33000 -> -32536 */
}

void uchar_product_truncates(void) {
    unsigned char x = 200;
    unsigned char y = 2;
    unsigned char result = x * y;   /* 400 -> 144 */
}

void schar_difference_truncates(void) {
    char c = -100;
    char d = 50;
    char result = c - d;       /* -150 -> 106 */
}

void assigned_after_declaration(void) {
    int n = 300;
    unsigned char c;
    c = n;                     /* 300 -> 44 */
}
