/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and maintainer ruling, rulings walk-through Q9
 * Status: PASS - goto retry returns to code before the switch; nothing leaves it for the end
 */

int settle(int state) {
retry:
  switch (state) {
    case 0:
      state = 1;
      goto retry;
    default:
      return state;
  }
}
