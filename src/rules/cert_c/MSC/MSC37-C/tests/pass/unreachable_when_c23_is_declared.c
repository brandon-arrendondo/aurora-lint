/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: PASS - C23 unreachable() ends the path once the edition is declared
 * Settings: c_standard=c23
 */

#include <stddef.h>

int sign(int x) {
  if (x > 0) {
    return 1;
  }
  if (x <= 0) {
    return -1;
  }
  unreachable();
}
