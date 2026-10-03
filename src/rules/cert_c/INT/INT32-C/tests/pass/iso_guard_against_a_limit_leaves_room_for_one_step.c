/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * Without a declared data model an int has no known width, so the side of
 * its range that nothing bounds is the type's own limit, whatever the width
 * is. A guard against another int moves that side by the distance the guard
 * states: after `i < limit`, i is at most one below that limit, so `i + 1`
 * reaches it and no further. Reading the open side as the limit itself
 * would make the sum one past it.
 */

int next_index(int i, int limit) {
    if (i < limit) {
        return i + 1;
    }
    return 0;
}

int previous_index(int i, int limit) {
    if (i > limit) {
        return i - 1;
    }
    return 0;
}
