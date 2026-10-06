/* A string whose text has `)` before `(` must not reverse an allocation-count slice. */
void f(void) {
  const char *p = ")malloc(";
  (void)sizeof p;
}
