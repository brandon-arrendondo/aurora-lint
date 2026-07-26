/*
 * Rule: EXP20-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

void login(char *usr, char *pw) {
  User user = find_user(usr);
  if (strcmp((user->password),pw) == 0) {
    grantAccess();
  }
  else {
    denyAccess("Incorrect Password");
  }
}