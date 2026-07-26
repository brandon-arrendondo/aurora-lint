/*
 * Rule: MSC06-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC06-C violation
 */

void getPassword(void) {
  char pwd[64];
  if (retrievePassword(pwd, sizeof(pwd))) {
    /* Checking of password, secure operations, etc. */
  }
  ZeroMemory(pwd, sizeof(pwd));
}