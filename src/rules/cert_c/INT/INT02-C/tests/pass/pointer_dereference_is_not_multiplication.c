/*
 * Rule: INT02-C
 * Source: regression (task 1186)
 * Status: PASS - Should NOT trigger INT02-C violation
 *
 * The defect the previous implementation had: "unsigned short" appears
 * earlier in the file, and every later line here contains a `*` that is a
 * pointer declarator, a dereference or a pointer advance -- none of them a
 * multiplication. This was 99% of the rule's real-world output.
 */

unsigned short lookup_table[4];

void walk(unsigned char *input, unsigned char *output, unsigned long count) {
  unsigned char *cursor = input;
  unsigned long index = 0;

  while (index < count) {
    *output = *cursor;
    cursor += 1;
    output += 1;
    index += 1;
  }
}
