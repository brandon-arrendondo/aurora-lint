/*
 * Rule: INT02-C
 * Source: wiki
 * Status: EXPECTED_FAIL - real defect this rule does not yet detect
 *
 * A genuine INT02-C violation: ~port is evaluated after promotion to int, so
 * the shift operates on the promoted value. Detecting it needs promotion
 * reasoning about the operand of a unary operator, which is neither of the
 * two shapes this rule was scoped to. Kept here rather than
 * deleted so the gap stays visible.
 */

uint8_t port = 0x5a;
uint8_t result_8 = ( ~port ) >> 4;