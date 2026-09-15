/*
 * Rule: INT02-C
 * Source: regression (task 1213)
 * Status: FAIL - Should trigger INT02-C violation
 *
 * The operands are spelled with project integer aliases rather than standard
 * type names. Before the typedef chain was followed these classified as
 * unknown and the comparison was skipped -- the common case in embedded and
 * vendor code, which is the deployment target.
 */

typedef unsigned int u32;
typedef int s32;

int compare_aliases(s32 counter, u32 limit) {
  if (counter < limit) {
    return 1;
  }
  return 0;
}
