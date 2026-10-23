/*
 * Rule: EXP00-C
 * Source: aurora-lint
 * Status: FAIL - a bitwise operator whose operand is an ungrouped comparison
 *
 * `flags & mask == 0` reads as `flags & (mask == 0)`. The grouped comparison
 * on the line before it is not the finding.
 */
int test(int flags, int mask) {
    int grouped = flags & (mask == 0);
    return grouped | flags & mask == 0;
}
