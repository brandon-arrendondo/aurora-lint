/*
 * Rule: EXP20-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP20-C violation
 */

void login(char *usr, char *pw) {
  User user = find_user(usr);
  if (!strcmp((user->password),pw)) {
    grantAccess();
  }
  else {
    denyAccess("Incorrect Password");
  }
}