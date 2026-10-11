/*
 * Rule: MSC30-C
 * Source: testcases
 * Status: PASS - the file defines its own rand(), so the call is not the
 * standard library's
 */

static unsigned int state = 1;

static int rand(void) {
  state = state * 1103515245u + 12345u;
  return (int)(state >> 16);
}

int roll(void) {
  return rand() % 6;
}
