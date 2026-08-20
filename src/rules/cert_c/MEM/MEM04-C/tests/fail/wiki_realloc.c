/*
 * Rule: MEM04-C
 * Source: wiki
 * Status: FAIL - Should trigger MEM04-C violation
 */

void *func(size_t nsize) {
  char *p2;
  char *p = (char *)malloc(100);
  if (p == NULL) {
    /* Handle error */
  }

  /* ... */

  if ((p2 = (char *)realloc(p, nsize)) == NULL) {
    free(p);
    p = NULL;
    return NULL;
  }
  p = p2;
  return p;
}