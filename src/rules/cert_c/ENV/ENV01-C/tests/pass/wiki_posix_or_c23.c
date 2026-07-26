/*
 * Rule: ENV01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

void f() {
  char *path = NULL;
  /* Avoid assuming $PATH is defined or has limited length */
  const char *temp = getenv("PATH");
  if (temp != NULL) {
    path = strdup(temp);
    if (path == NULL) {
      /* Handle error condition */
    }
    /* Use path */
    free(path);
  }
}