/* Malformed: the string is never closed, so the `)malloc(` text runs into code. */
void f(void) {
  const char *p = ")malloc(;
  (void)sizeof p;
}
