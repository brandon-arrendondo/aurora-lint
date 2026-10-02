/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * Without a declared data model an int has no known width, so the side of its
 * range that no guard bounds is the type's own limit, whatever the width is.
 * Adding one to a value known to be at most 1000 cannot pass that limit on
 * any width, and neither can subtracting one from a value known to be at
 * least -1000.
 */

int next(int value) {
    if (value > 1000) {
        return 0;
    }
    return value + 1;
}

int previous(int value) {
    if (value < -1000) {
        return 0;
    }
    return value - 1;
}

long next_long(long value) {
    if (value > 1000) {
        return 0;
    }
    return value + 1;
}

long previous_long(long value) {
    if (value < -1000) {
        return 0;
    }
    return value - 1;
}
