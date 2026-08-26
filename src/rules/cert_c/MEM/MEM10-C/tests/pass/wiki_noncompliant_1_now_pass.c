/*
 * Rule: MEM10-C
 * Source: wiki
 * Status: PASS - This is CERT's original wiki "noncompliant" example, but it
 * is a single, isolated NULL guard in the file with no evidence of
 * duplication or inconsistency (no other ad hoc check, no bypassed shared
 * validator elsewhere in the file). Task 595: a lone early-return-style
 * NULL-guard idiom must not fire MEM10-C on its own; the rule's real target
 * is ad hoc, duplicated, or inconsistent validation, not any single check.
 */

void incr(int *intptr) {
  if (intptr == NULL) {
    /* Handle error */
  }
  (*intptr)++;
}
