/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: PASS - the last arm's final statement is a dead break after a return
 */

const char *name(int format) {
  switch (format) {
    case 0: return "ZERO"; break;   // first
    case 1: return "ONE"; break;    // second
    default: return "UNKNOWN"; break;
  }
}
