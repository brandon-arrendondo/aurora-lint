/*
 * Rule: EXP14-C
 * Source: task-follow-up (hostap-style bare narrow typedef, real TP shape)
 * Status: FAIL - Should trigger EXP14-C violation
 * Description: A project-local narrow-width typedef (the common
 * Linux-kernel-style u8/u16 spelling) must still be recognized as narrower
 * than int via the typedef chain, not just the builtin uint8_t/uint16_t
 * spellings.
 */

typedef unsigned char u8;

void complement_u8(void) {
    u8 mask = 0x0F;
    u8 result = (~mask) >> 4;
}
