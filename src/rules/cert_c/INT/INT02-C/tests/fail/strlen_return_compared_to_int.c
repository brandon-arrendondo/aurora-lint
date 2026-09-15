/*
 * Rule: INT02-C
 * Source: regression (task 1213)
 * Status: FAIL - Should trigger INT02-C violation
 *
 * The classic shape: strlen returns size_t, so the signed loop counter is
 * converted to unsigned. Before call returns were resolved this was skipped
 * because the operand is not a bare identifier.
 */

#include <string.h>

int count_chars(const char *text, char wanted) {
  int i;
  int found = 0;

  for (i = 0; i < strlen(text); i++) {
    if (text[i] == wanted) {
      found++;
    }
  }
  return found;
}
