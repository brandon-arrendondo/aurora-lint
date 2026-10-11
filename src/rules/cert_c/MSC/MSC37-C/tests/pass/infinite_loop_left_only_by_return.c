/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: PASS - nothing leaves the loop except return
 */

int first_positive(const int *v) {
  while (1) {
    if (*v > 0) {
      return *v;
    }
    v++;
  }
}
