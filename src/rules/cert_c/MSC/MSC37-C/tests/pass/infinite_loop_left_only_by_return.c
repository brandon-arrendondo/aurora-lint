/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and maintainer ruling, rulings walk-through Q9
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
