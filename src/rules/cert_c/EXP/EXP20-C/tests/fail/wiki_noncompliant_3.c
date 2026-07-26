/*
 * Rule: EXP20-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP20-C violation
 */

int validateUser(User usr) {
  if(listContains(validUsers, usr)) {
    return 1;
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