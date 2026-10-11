/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: FAIL - the loop is left by break, then control reaches the end
 */

int next(int *queue, int n) {
  while (1) {
    if (n-- == 0) {
      break;
    }
    if (queue[n] > 0) {
      return queue[n];
    }
  }
}
