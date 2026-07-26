/*
 * Rule: MSC06-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

void getPassword(void) {
  char pwd[64];
  if (retrievePassword(pwd, sizeof(pwd))) {
    /* Checking of password, secure operations, etc. */
  }
  SecureZeroMemory(pwd, sizeof(pwd));
}