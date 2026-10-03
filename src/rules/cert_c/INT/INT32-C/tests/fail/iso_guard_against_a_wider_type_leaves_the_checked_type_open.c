/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * `i < count` leaves i below the limit of COUNT's type, which is i's own limit
 * only when count is no wider than i. After a comparison against a long or a
 * long long, i can still be anywhere in int, so `i + 1` and `i - 1` can pass
 * int's limit on every width ISO C allows. A declared target with a 32-bit int
 * reports the long long case too; a guard against an int does not
 * (tests/pass/iso_guard_against_a_limit_leaves_room_for_one_step.c).
 */

void use_int(int value);

void after_a_long_count(int i, long count) {
    if (i < count) {
        use_int(i + 1); /* VIOLATION */
    }
}

void after_a_long_long_count(int i, long long count) {
    if (i < count) {
        use_int(i + 1); /* VIOLATION */
    }
}

void after_a_long_floor(int i, long floor) {
    if (i > floor) {
        use_int(i - 1); /* VIOLATION */
    }
}

void after_a_long_long_floor(int i, long long floor) {
    if (i > floor) {
        use_int(i - 1); /* VIOLATION */
    }
}
