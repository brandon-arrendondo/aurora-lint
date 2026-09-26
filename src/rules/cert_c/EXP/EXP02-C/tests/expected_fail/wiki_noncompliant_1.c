/*
 * Rule: EXP02-C
 * Source: wiki, CERT EXP02-C "Noncompliant Code Example", verbatim
 * Status: EXPECTED_FAIL - CERT's own noncompliant example, not detected yet
 *
 * The second operand of || has a side effect (p = malloc(...)) that runs only
 * when p is NULL, so whether malloc() was called depends on short-circuit
 * evaluation. CERT's stated consequence is the later free(p) of a pointer
 * that may not have come from malloc(). The rule does not report this
 * guard-then-assign shape today. It returns to tests/fail/ when it does.
 */

char *p = /* Initialize; may or may not be NULL */

if (p || (p = (char *) malloc(BUF_SIZE)) ) {
  /* Perform some computation based on p */
  free(p);
  p = NULL;
} else {
  /* Handle malloc() error */
  return;
}
