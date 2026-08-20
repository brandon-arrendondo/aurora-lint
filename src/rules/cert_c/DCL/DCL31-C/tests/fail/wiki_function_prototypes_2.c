/*
 * Rule: DCL31-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL31-C violation
 *
 * Noncompliant: file_b.c calls func() with no prototype in scope
 * (func is defined with a different signature in file_a.c, see
 * wiki_function_prototypes.c).
 */

/* file_b.c source file, no prototype for func() in scope */
void call_func(void) {
  func(1, 2);
}