/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and maintainer ruling, rulings walk-through Q9
 * Status: FAIL - the file's own unreachable() is not the C23 macro
 * Settings: c_standard=c23
 */

extern void log_unreachable(void);

void unreachable(void) {
  log_unreachable();
}

int sign(int x) {
  if (x > 0) {
    return 1;
  }
  if (x <= 0) {
    return -1;
  }
  unreachable();
}
