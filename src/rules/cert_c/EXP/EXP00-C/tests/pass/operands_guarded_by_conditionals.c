/*
 * Rule: EXP00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP00-C violation
 *
 * An operator chain whose operands are each compiled or not by a
 * conditional. The conditions (`(MODE&1)==1`, `LEVEL<4`) are directives,
 * not operands: in every configuration the expression is a plain `|` chain.
 */
#define FLAG_A 1
#define FLAG_B 2
#define FLAG_C 4
#ifndef MODE
# define MODE 3
#endif

unsigned set_flags(unsigned flags) {
  flags |= FLAG_A
#if (MODE&1)==1
           | FLAG_B
#endif
#if LEVEL<4
           | FLAG_C
#endif
           ;
  return flags;
}

unsigned sum_parts(unsigned a, unsigned b, unsigned c) {
  unsigned x = a +
#ifdef WITH_B
      b +
#endif
      c;
  return x;
}
