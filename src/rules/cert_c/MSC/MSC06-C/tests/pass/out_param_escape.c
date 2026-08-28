/*
 * Rule: MSC06-C
 * Source: task 565 (local buffer zeroed then handed out through an
 * out-parameter)
 * Status: PASS - buf escapes via *out, so it persists past this call and
 * never goes out of scope here.
 */

void *malloc(unsigned long size);

void allocAndClear(unsigned long n, char **out) {
  char *buf = malloc(n);
  if (buf) {
    memset(buf, 0, n);
  }
  *out = buf;
}
