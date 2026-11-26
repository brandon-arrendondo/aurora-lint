/*
 * Rule: DCL13-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL13-C violation
 * Expect: count=1
 *
 * CERT's noncompliant example with a definition of strcat_nc() that, like
 * strcat(), appends s2 to s1 without changing what s2 points to. s2 is
 * reported at the definition.
 */

char *strcat_nc(char *s1, char *s2);

char *strcat_nc(char *s1, char *s2) {
  char *end = s1;
  while (*end) {
    end++;
  }
  while (*s2) {
    *end++ = *s2++;
  }
  *end = '\0';
  return s1;
}

char *c_str1 = "c_str1";
const char *c_str2 = "c_str2";
char c_str3[9] = "c_str3";
const char c_str4[9] = "c_str4";

void use(void) {
  strcat_nc(c_str3, c_str2);  /* Compiler warns that c_str2 is const */
  strcat_nc(c_str1, c_str3);  /* Attempts to overwrite string literal! */
  strcat_nc(c_str4, c_str3);  /* Compiler warns that c_str4 is const */
}
