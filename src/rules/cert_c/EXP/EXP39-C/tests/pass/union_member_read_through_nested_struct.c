/*
 * Rule: EXP39-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP39-C violation
 *
 * Reading a union member other than the one last written is compliant,
 * as in CERT's compliant solution, including through a struct member.
 */

union word {
  unsigned int whole;
  struct {
    unsigned short lo;
    unsigned short hi;
  } halves;
};

unsigned short high_half(unsigned int v) {
  union word w;
  w.whole = v;
  return w.halves.hi;
}
