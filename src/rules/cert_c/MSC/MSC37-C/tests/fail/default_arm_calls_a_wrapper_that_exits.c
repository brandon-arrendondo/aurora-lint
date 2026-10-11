/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
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
