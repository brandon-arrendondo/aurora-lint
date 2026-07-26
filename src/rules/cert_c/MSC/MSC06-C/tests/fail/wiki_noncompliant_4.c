/*
 * Rule: MSC06-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC06-C violation
 */

static int always = 1;
int main(void) {
  while (always) { }
}