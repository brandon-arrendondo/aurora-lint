/*
 * Rule: MSC24-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#define __STDC_WANT_LIB_EXT1__
#include <string.h>
#include <stdio.h>
 
enum { BUFFERSIZE = 256 };

void complain(const char *msg) {
  static const char prefix[] = "Error: ";
  static const char suffix[] = "\n";
  char buf[BUFFERSIZE];

  strcpy_s(buf, BUFFERSIZE, prefix);
  strcat_s(buf, BUFFERSIZE, msg);
  strcat_s(buf, BUFFERSIZE, suffix);
  fputs(buf, stderr);
}