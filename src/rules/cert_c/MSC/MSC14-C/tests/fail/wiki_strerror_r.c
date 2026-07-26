/*
 * Rule: MSC14-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC14-C violation
 */

void f() {
  char buf[BUFSIZ];
  fprintf(stderr, "Error: %s\n",
          strerror_r(errno, buf, sizeof buf));
}