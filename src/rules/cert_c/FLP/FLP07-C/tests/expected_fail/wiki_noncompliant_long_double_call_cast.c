/*
 * Rule: FLP07-C
 * Source: wiki, adapted from CERT FLP07-C "Noncompliant Code Example"
 * Status: EXPECTED_FAIL - noncompliant under CERT's text, not detected yet
 *
 * This file used to sit in tests/pass/ under the name of CERT's "Compliant
 * Solution (within the Function)", but it is neither compliant solution.
 * calc_percentage() keeps the noncompliant example's uncast
 * `return value * 0.1f;`, whose result may carry more range or precision
 * than float. CERT's "Compliant Solution (Outside the Function)" fixes that
 * with a (float) cast at the call; the cast here is to (long double), which
 * does not narrow, so the excess precision CERT warns about is not removed.
 */

float calc_percentage(float value) {
  return value * 0.1f;
}

void float_routine(void) {
  float value = 99.0f;
  long double percentage;

  percentage = (long double) calc_percentage(value);
}
