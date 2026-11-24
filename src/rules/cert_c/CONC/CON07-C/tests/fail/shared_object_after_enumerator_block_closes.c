/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=1
 *
 * An enumerator declared in an inner block hides the shared object of the
 * same name only until that block closes; after it, `total` is the shared
 * object again.
 */

static int total, hits;

int tally(void) {
  {
    enum { total = 3 };
    hits = total;
  }
  return total + hits;
}
