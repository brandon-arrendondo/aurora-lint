/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * A guard against an operand of the checked type bounds the value below that
 * type's limit, wherever the limit is. Casting the wider count to int first
 * makes the comparison an int comparison, so `i + 1` after `i < (int) count`
 * reaches the limit and no further.
 */

void use_int(int value);

void after_an_int_cast(int i, long count) {
    if (i < (int) count) {
        use_int(i + 1);
    }
}

void after_an_int_count(int i, int count) {
    if (i < count) {
        use_int(i + 1);
    }
}
