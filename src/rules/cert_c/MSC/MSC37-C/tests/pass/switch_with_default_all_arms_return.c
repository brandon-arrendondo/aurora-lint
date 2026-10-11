/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: PASS - every arm returns and a default covers the rest
 */

enum color { RED, GREEN, BLUE };

int weight(int c) {
  switch (c) {
    case RED:
      return 1;
    case GREEN:
      return 2;
    default:
      return 3;
  }
}
