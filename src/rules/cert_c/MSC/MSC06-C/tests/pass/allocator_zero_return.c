/*
 * Rule: MSC06-C
 * Source: task 565 (sqlite3MallocZero-style allocator helper)
 * Status: PASS - the zeroed buffer is returned, so it never goes out of
 * scope at the memset site; this is not a dead store.
 */

void *malloc(unsigned long size);

void *allocZero(unsigned long n) {
  void *p = malloc(n);
  if (p) {
    memset(p, 0, n);
  }
  return p;
}
