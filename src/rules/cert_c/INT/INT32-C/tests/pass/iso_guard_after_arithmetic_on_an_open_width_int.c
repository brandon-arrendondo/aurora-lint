/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * Without a declared data model an int has no known width, so the side of
 * its range that no guard bounds is the type's own limit, whatever the width
 * is. Arithmetic on the variable moves that limit by the constant involved
 * (the sum below is bounded from above by the guard, so it cannot overflow,
 * and leaves the bottom of the range a few steps above the type's minimum),
 * and a later add of one still cannot pass the limit on any width.
 */

int after_a_bounded_sum(int value) {
    if (value > 1000) {
        return 0;
    }
    value = value + 4;
    return value + 1;
}

int after_a_bounded_difference(int value) {
    if (value < -1000) {
        return 0;
    }
    value = value - 4;
    return value - 1;
}
