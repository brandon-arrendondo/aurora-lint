/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and maintainer ruling, rulings walk-through Q9
 * Status: FAIL - an exit-only wrapper is not credited: only a trusted noreturn function ends the path
 */

extern void die(const char *why);

const char *name(int format) {
  switch (format) {
    case 0:
      return "ZERO";
    default:
      die("bad format");
      break;
  }
}
