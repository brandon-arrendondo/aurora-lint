/*
 * Rule: MSC24-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC24-C violation
 */

#include <string.h>
#include <stdio.h>
 
enum { BUFSIZE = 32 };
void complain(const char *msg) {

  static const char prefix[] = "Error: ";
  static const char suffix[] = "\n";
  char buf[BUFSIZE];

  strcpy(buf, prefix);
  strcat(buf, msg);
  strcat(buf, suffix);
  fputs(buf, stderr);
}