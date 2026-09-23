/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - Should trigger INT02-C violation
 *
 * wiki_comparison.c with the operands renamed off the CERT example's `si`
 * and `ui`. The previous implementation keyed on those two spellings, so
 * this identical defect was invisible to it.
 */

void compare(void) {
  int counter = -1;
  unsigned int limit = 1;

  if (counter < limit) {
    return;
  }
}
