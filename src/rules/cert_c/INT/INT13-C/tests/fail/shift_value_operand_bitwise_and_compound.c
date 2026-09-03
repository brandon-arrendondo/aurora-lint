/*
 * Rule: INT13-C
 * Source: sqlite src/wal.c sqlite3WalReadFrame (task 754)
 * Status: FAIL - Should trigger INT13-C violation
 *
 * Guard rail: the shifted VALUE can itself be a non-shift bitwise
 * expression (`sz & 0x0001`), which must still resolve to `sz`. Only a
 * nested SHIFT's count operand is off-limits, not every compound operand.
 */

void shift_value_operand_bitwise_and_compound(void) {
    int sz = 10;
    unsigned int result = (sz & 0x0001) << 16;
}
