/*
 * Rule: EXP14-C
 * Source: task-follow-up
 * Status: FAIL - Should trigger EXP14-C violation
 * Description: Left-shifting a genuinely narrow operand without a cast is
 * still a real promotion hazard -- the `<<` path needs the same
 * declared-width check as the unary `~` path, not just the `~` fixtures.
 */

#include <stdint.h>

void shift_narrow(void) {
    uint8_t val = 0xAA;
    uint8_t shifted = val << 2;
}
