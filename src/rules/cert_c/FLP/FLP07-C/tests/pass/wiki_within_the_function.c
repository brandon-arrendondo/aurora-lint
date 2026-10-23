/*
 * Rule: FLP07-C
 * Source: wiki, CERT FLP07-C "Compliant Solution (within the Function)"
 * Status: PASS - the callee casts its own return value
 *
 * calc_percentage() returns (float)(value * 0.1f), so its result has no more
 * range or precision than float when it reaches the long double.
 */

float calc_percentage(float value) {
  return (float)(value * 0.1f);
}

void float_routine(void) {
  float value = 99.0f;
  long double percentage;

  percentage = calc_percentage(value);
}
