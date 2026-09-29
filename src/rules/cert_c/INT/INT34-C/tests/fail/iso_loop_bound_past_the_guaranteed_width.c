/*
 * Rule: INT34-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * ISO C guarantees unsigned int only 16 bits, so a loop that shifts it by up
 * to 31 shifts by its width or more on a conforming target: undefined. The
 * same loop on a declared LP64 target is bounded (tests/pass/
 * testcases_loop_bounded_shifts.c).
 */

unsigned int shift_in_for_loop(unsigned int x) {
    unsigned int result = 0;
    for (int i = 0; i < 32; i++) {
        result |= (x << i); /* VIOLATION */
    }
    return result;
}
