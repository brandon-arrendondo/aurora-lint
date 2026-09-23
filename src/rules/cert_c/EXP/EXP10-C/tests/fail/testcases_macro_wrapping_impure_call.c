/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP10-C violation
 * Description: A macro is only pure if its expansion is. READ(p) expands
 * to a port read with device side effects, so READ(A) | READ(B) is the
 * same unsequenced pair as in8(A) | in8(B) (seL4 pic.c:85, the one true
 * positive in an earlier fix's adjudication).
 */

extern unsigned char in8(unsigned short port);
#define READ(p) in8(p)
#define PIC1 0x20
#define PIC2 0xA0

unsigned short pic_get_irr(void) {
  return (((unsigned short)READ(PIC2)) << 8) | READ(PIC1);
}
