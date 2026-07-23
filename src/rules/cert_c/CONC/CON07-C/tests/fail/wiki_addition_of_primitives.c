/*
 * Rule: CON07-C
 * Source: wiki
 * Status: FAIL - Should trigger CON07-C violation
 */

static int a;
static int b;
 
int get_sum(void) {
  return a + b;
}
 
void set_values(int new_a, int new_b) {
  a = new_a;
  b = new_b;
}