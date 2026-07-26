/*
 * Rule: MSC06-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC06-C violation
 */

void getPassword(void) {
  char pwd[64];
  if (GetPassword(pwd, sizeof(pwd))) {
    /* Checking of password, secure operations, etc. */
  }
  memset(pwd, 0, sizeof(pwd));
}