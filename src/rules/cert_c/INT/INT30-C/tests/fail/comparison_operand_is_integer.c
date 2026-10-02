/*
 * Rule: INT30-C
 * Source: synthetic
 * Status: FAIL - Should trigger INT30-C violation
 *
 * A comparison of doubles has type int (C11 6.5.8p6), so this is unsigned
 * integer addition that wraps when u is UINT_MAX and d > 0.5.
 */
unsigned add_comparison(unsigned u, double d) {
    return u + (d > 0.5); // violation
}
