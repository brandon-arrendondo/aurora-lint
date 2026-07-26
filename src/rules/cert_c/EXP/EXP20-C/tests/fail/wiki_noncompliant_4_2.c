/*
 * Rule: EXP20-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP20-C violation
 */

errno_t validateUser(User usr) {
  if(list_contains(allUsers, usr) == 0) {
    return 303; /* User not found error code */
  }
  if(list_contains(validUsers, usr) == 0) {
    return 304; /* Invalid user error code */
  }

  return 0;
}

void processRequest(User usr, Request request) {
  if(!validateUser(usr)) {
    return "invalid user";
  }
  else {
    serveResults();
  }
}