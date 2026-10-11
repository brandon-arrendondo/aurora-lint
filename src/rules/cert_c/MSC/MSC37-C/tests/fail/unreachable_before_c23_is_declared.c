/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and maintainer ruling, rulings walk-through Q9
 * Status: FAIL - unreachable() is C23: with no edition declared the call proves nothing
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
