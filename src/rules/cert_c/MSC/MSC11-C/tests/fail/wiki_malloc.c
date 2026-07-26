/*
 * Rule: MSC11-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC11-C violation
 */

char *dupstring(const char *c_str) {
  size_t len;
  char *dup;

  len = strlen(c_str);
  dup = (char *)malloc(len + 1);
  assert(NULL != dup);

  memcpy(dup, c_str, len + 1);
  return dup;
}