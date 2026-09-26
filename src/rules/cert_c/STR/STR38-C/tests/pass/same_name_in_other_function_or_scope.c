/*
 * Rule: STR38-C
 * Source: regression
 * Status: PASS - each string argument's width comes from its own declaration
 *
 * A name is not a variable. `buf` is wide in one function and narrow in
 * another; `s` is narrow in the function and wide only in an inner block;
 * `zCopy` merely contains the letter of a wide local's name. Each call
 * matches the width its argument is declared with, so none is a violation.
 */

#include <string.h>
#include <wchar.h>

void wide_buf(void) {
  wchar_t *buf = L"w";
  wcslen(buf);
}

void narrow_buf(void) {
  char *buf = "n";
  strlen(buf);
}

void shadowed(void) {
  char s[4] = "abc";
  {
    wchar_t s[4] = L"abc";
    wcslen(s);
  }
  strlen(s);
}

size_t substring(const char *zCopy) {
  wchar_t o[2] = L"x";
  (void)o;
  return strlen(zCopy);
}
