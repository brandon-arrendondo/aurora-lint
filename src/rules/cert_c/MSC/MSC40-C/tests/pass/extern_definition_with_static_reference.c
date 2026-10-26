/*
 * Rule: MSC40-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC40-C violation
 *
 * An external definition that is not inline may keep state in a static
 * object and read an identifier with internal linkage.
 */

static int seed = 1;

extern unsigned next_value(void) {
  static unsigned counter = 1;
  return counter++ + (unsigned)seed;
}
