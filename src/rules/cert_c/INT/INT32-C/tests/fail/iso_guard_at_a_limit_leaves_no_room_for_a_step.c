/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * `i <= limit` allows i to be the limit itself, so `i + 1` can pass it on
 * every width; the guard moved the open side by nothing
 * (tests/pass/iso_guard_against_a_limit_leaves_room_for_one_step.c).
 */

int next_index(int i, int limit) {
    if (i <= limit) {
        return i + 1; /* VIOLATION */
    }
    return 0;
}
