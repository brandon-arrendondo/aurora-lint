/*
 * Rule: INT30-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * After the guard the counter is at least 70000, and 70000 * 1103515245
 * exceeds what any unsigned int can hold, whatever its width, so the
 * product wraps. Without a declared data model unsigned int has no upper
 * bound, the range of the product leaves what the analysis can represent,
 * and the lower end alone shows the wrap. It is reported under a declared
 * model too.
 */

unsigned int scale(void) {
    static unsigned int level;

    level += 1;
    if (level < 70000) {
        return 0;
    }
    return level * 1103515245u; /* VIOLATION */
}
