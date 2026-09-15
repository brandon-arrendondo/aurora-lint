/*
 * Rule: INT02-C
 * Source: regression (task 1213)
 * Status: FAIL - Should trigger INT02-C violation
 *
 * The unsigned operand is a struct field rather than a bare identifier.
 */

struct header {
  unsigned int length;
  int flags;
};

int fits(struct header *hdr, int available) {
  if (available < hdr->length) {
    return 0;
  }
  return 1;
}
