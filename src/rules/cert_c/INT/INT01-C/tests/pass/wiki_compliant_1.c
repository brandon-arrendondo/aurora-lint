/*
 * Rule: INT01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

char *copy(size_t n, const char *c_str) {
  size_t i;
  char *p;

  if (n == 0) {
    /* Handle unreasonable object size error */
  }
  p = (char *)malloc(n);
  if (p == NULL) {
    return NULL;  /* Indicate malloc failure */
  }
  for (i = 0; i < n; ++i) {
    p[i] = *c_str++;
  }
  return p;
}

/* ... */

char c_str[] = "hi there";
char *p = copy(sizeof(c_str), c_str);