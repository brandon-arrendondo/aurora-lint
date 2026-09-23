/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP10-C violation
 * Description: A project function-like macro whose expansion has no side
 * effects (bit helpers, cast helpers, accessors) is not a side-effecting
 * call, so read_reg(x) & MASK(n) has one call, not two. seL4's
 * apic_read_reg(APIC_LOGICAL_DEST) & MASK(XAPIC_LDR_SHIFT), pic_get_isr() &
 * BIT(15), and Lua's cast(OpCode, cast_int(a) - cast_int(b)) (an earlier fix
 * mechanism 2).
 */

#define BIT(n) (1ul << (n))
#define MASK(n) (BIT(n) - 1ul)
#define GET_INDEX(x) (((x) >> 12) & MASK(9))
#define cast(t, exp) ((t)(exp))
#define cast_int(i) cast(int, (i))
#define FLAG_IS_SET(v, f) (((v) & (f)) != 0)

typedef enum { OP_ADD, OP_SUB } OpCode;
extern unsigned long read_reg(int reg);
extern unsigned pic_get_isr(void);

int f(int reg, int opr, int baser, int base) {
  unsigned long ldr = read_reg(reg) & MASK(8);
  int fired = FLAG_IS_SET(pic_get_isr(), BIT(15));
  unsigned long idx = GET_INDEX(read_reg(reg + 1));
  OpCode op = cast(OpCode, (cast_int(opr) - cast_int(baser)) + cast_int(base));
  return (int)ldr + fired + (int)idx + op;
}
