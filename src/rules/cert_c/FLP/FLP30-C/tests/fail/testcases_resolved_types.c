/*
 * Rule: FLP30-C
 * Source: testcases
 * Status: FAIL - Should trigger FLP30-C violation
 *
 * The counter's type is read from its declaration with typedefs resolved,
 * not from the spelling of the for initializer: a typedef of double, a
 * counter declared before the loop and assigned in the initializer, an
 * empty initializer, and a comma initializer.
 */

#include <math.h>

typedef double real_t;

void typedef_counter(void) {
  for (real_t r = 0.0; r < 1.0; r += 0.1) {
  }
}

void float_t_counter(void) {
  float_t f;
  for (f = 0; f != 10; f++) {
  }
}

void empty_init(float y) {
  for (; y > 0.0f; y -= 0.5f) {
  }
}

void comma_init(void) {
  int i;
  double z;
  for (i = 0, z = 0; z < 5; z += 1.0) {
  }
}
