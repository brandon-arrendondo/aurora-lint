/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and maintainer ruling, rulings walk-through Q9
 * Status: PASS - for (;;) is left only by return
 */

int first_positive(const int *v) {
  for (;;) {
    if (*v > 0) {
      return *v;
    }
    v++;
  }
}
