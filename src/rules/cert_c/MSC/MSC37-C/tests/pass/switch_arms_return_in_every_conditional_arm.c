/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: PASS - every configuration of the arm returns, so the break after it is dead
 */

int option(int which) {
  switch (which) {
    case 0:
#if defined(FEATURE_A)
      return 1;
#else
      return 2;
#endif
      break;
    default:
      return 3;
  }
}
