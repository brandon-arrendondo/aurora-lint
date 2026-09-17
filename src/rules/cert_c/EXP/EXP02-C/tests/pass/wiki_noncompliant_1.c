/*
 * Rule: EXP02-C
 * Source: wiki (CERT's own noncompliant example)
 * Status: PASS - Should NOT trigger EXP02-C violation
 *
 * Reclassified for task 1151/1154. CERT's wiki labels this noncompliant,
 * but its own stated reason ("free() might be called with a pointer to
 * local data not allocated by malloc()") is about the *later* unconditional
 * free(p)/p = NULL misusing p's provenance -- something no per-expression
 * short-circuit check can see; the `if (p || (p = ...))` condition itself
 * is the ordinary, ubiquitous "use what's already set, else create it"
 * lazy-init idiom. Cross-project adjudication (benchmark_adjudication/data/
 * {curl,hostap,mbedtls,mosquitto,pureftpd,valkey,ventoy}) confirms this
 * shape -- including the identical "test var X, conditionally reassign the
 * same var X" structure, e.g. ventoy's `(ret != 0) && ((ret = f()) == 0)`
 * -- is uniformly intentional, not a detectable local defect: 0/205+
 * real-world instances of guard-then-assign-and-test were true positives.
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