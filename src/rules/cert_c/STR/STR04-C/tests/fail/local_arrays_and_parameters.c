/*
 * Rule: STR04-C
 * Source: wiki (the noncompliant example, inside a function)
 * Status: FAIL - Should trigger STR04-C violation
 * Expect: count=5
 *
 * CERT's example declares its arrays where the statements that use them
 * run, so they are locals. Each argument is typed by the declaration its
 * name resolves to, a local or a parameter.
 */

#include <string.h>

size_t lengths(const unsigned char *param) {
  size_t len;
  char cstr[] = "char string";
  signed char scstr[] = "signed char string"; /* Expect: here */
  unsigned char ucstr[] = "unsigned char string"; /* Expect: here */

  len = strlen(cstr);
  len = strlen(scstr); /* Expect: here */
  len = strlen(ucstr); /* Expect: here */
  len += strlen(param); /* Expect: here */
  return len;
}
