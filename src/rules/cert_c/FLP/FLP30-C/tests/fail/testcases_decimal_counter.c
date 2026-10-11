/*
 * Rule: FLP30-C
 * Source: testcases
 * Status: FAIL - Should trigger FLP30-C violation
 *
 * Decimal floating types are in scope: C23 makes them floating types, and
 * their fixed precision still loses a step against a large value.
 */

void decimal_counter(void) {
  for (_Decimal64 d = 0.0DD; d < 1.0DD; d += 0.1DD) {
  }
}
