/*
 * Rule: ARR30-C
 * Source: task 1273 (valkey src/valkey-cli.c clusterManagerCommandReshard,
 *         lines 7755 / 7768 / 7891)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: one function declares `buf` three times, in three blocks, at
 *         three sizes. Every access below is within the bound of the
 *         declaration in scope at that access. The per-function buffer
 *         prescan is keyed by name and kept whichever declaration it saw
 *         LAST (`buf[4]`), so `buf[5]` against `buf[6]` and `buf[100]`
 *         against `buf[255]` were both reported as out of bounds of a
 *         four-byte buffer declared a hundred lines later -- a size that is
 *         not the one on the line (ADR-0005, ADR-0006). The lookup now
 *         resolves the occurrence to its own declaration.
 */

int prompt(int first)
{
    if (first) {
        char buf[6];
        buf[5] = '\0';
    }

    char buf[255];
    buf[100] = '\0';
    buf[254] = '\0';

    for (;;) {
        char buf[4];
        buf[3] = '\0';
        break;
    }
    return buf[0];
}
