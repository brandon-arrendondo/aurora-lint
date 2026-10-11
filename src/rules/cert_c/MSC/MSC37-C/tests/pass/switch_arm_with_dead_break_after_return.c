/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: PASS - a break right after a return is dead code, not a way out of the switch
 */

int size_of(int kind) {
  switch (kind) {
    case 1:
      return 4; /* the kind-1 size */
      break;
    default:
      return 8;
  }
}
