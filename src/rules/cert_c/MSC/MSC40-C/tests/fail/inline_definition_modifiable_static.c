/*
 * Rule: MSC40-C
 * Source: synthetic
 * Status: FAIL - Should trigger MSC40-C violation
 * Expect: count=1
 *
 * An inline definition with external linkage defines a modifiable object
 * with static storage duration.
 */

inline unsigned next_value(void) {
  static unsigned counter = 1; /* Expect: here */
  return counter++;
}
