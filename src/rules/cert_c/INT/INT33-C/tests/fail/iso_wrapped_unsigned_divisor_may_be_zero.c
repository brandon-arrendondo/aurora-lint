/*
 * Rule: INT33-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * Unsigned arithmetic wraps, so the result of the multiplication and
 * addition can be any value of the type, zero included: nothing proves the
 * divisor non-zero, and the divisions are reported.
 */

unsigned int quotient(unsigned int seed, unsigned int total) {
    seed = seed * 1103515245u + 12345u;
    return total / seed; /* VIOLATION */
}

unsigned int remainder_of(unsigned int seed, unsigned int total) {
    seed = seed * 1103515245u + 12345u;
    return total % seed; /* VIOLATION */
}
