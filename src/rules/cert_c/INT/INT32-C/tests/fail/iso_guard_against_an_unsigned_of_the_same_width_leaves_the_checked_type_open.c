/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * `i < u` converts i to unsigned int, so it says nothing below i's own limit
 * when u is above INT_MAX: i can still be INT_MAX at `i + 1`. An unsigned
 * operand as wide as the checked type is not a bound of that type.
 */

int use_index(int i);

int bounded_by_unsigned(int i, unsigned u) {
    if (i < u) {
        return use_index(i + 1); /* VIOLATION */
    }
    return 0;
}

int bounded_by_unsigned_reversed(int i, unsigned u) {
    if (u > i) {
        return use_index(i + 1); /* VIOLATION */
    }
    return 0;
}
