/*
 * Rule: FLP07-C
 * Source: wiki
 * Status: FAIL - Should trigger FLP07-C violation
 */

float calc_percentage(float value) {
  return value * 0.1f;
}

void float_routine(void) {
  float value = 99.0f;
  long double percentage;

  percentage = calc_percentage(value); /* Expect: here */
}