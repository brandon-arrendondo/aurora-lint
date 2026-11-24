/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * A block-scope enumerator of the same name hides a shared object, so the
 * function reads one shared object, once, and writes only its own local.
 */

static int limit, used;

int remaining(void) {
  enum { limit = 3 };
  return limit - used;
}

void scale(void) {
  enum { limit = 2 };
  int local = limit;
  local++;
  (void)local;
}
