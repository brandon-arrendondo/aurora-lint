/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and maintainer ruling, rulings walk-through Q9
 * Status: FAIL - the goto leaves the loop for code after it, which falls off the end
 */

int scan(int x) {
  while (1) {
    if (x > 10) {
      goto done;
    }
    x++;
  }
done:
  x = 0;
}
