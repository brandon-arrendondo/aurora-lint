/*
 * Rule: MSC11-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

char *dupstring(const char *c_str) {
  size_t len;
  char *dup;

  len = strlen(c_str);
  dup = (char*)malloc(len + 1);
  /* Detect and handle memory allocation error */
  if (NULL == dup) {
      return NULL; 
  }

  memcpy(dup, c_str, len + 1);
  return dup;
}