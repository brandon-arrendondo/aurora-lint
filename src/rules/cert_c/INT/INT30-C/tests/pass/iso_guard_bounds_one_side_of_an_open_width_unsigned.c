/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * Without a declared data model an unsigned int has no known width, so the
 * side of its range that no guard bounds is the type's own limit, whatever
 * the width is. Subtracting one from a value known to be at least one cannot
 * wrap on any width, and neither can adding one to a value known to be at
 * most 1000.
 */

unsigned int previous(unsigned int value) {
    if (value < 1) {
        return 0;
    }
    return value - 1;
}

unsigned long previous_long(unsigned long value) {
    if (value < 1) {
        return 0;
    }
    return value - 1;
}

unsigned int next(unsigned int value) {
    if (value > 1000) {
        return 0;
    }
    return value + 1;
}
