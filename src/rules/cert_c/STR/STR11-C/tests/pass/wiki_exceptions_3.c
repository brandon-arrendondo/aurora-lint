/*
 * Rule: STR11-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <string.h>
 
void func(void) {
  char s[10] = "abc";
  strcpy(&s[3], "def");
}