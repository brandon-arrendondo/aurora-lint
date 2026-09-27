/*
 * Rule: INT10-C
 * Source: regression
 * Status: FAIL - `x % y` has two signed operands
 *
 * An inner block declares its own `unsigned int x`. A function-wide name map
 * keeps one entry per name, and the inner declaration used to answer for
 * the outer `x`, so the remainder read as having an unsigned operand. The
 * occurrence's own declaration is the outer int.
 */

int wrap(int n, int y) {
    int x = n;
    int r = x % y;
    {
        unsigned int x = 0u;
        (void)x;
    }
    return r;
}
