/*
 * Rule: STR38-C
 * Source: regression
 * Status: FAIL - the width of a literal, a cast or a file-scope array is
 * read from the code itself
 *
 * An L"..." literal is a wide string and an unprefixed one is narrow; a cast
 * to wchar_t * or char * states the width it is used with; a file-scope
 * wchar_t array is wide inside every function.
 */

#include <string.h>
#include <wchar.h>

wchar_t global_wide[8];

size_t literal(void) {
  return strlen(L"wide");
}

size_t cast(void *p) {
  return wcslen((char *)p);
}

void global(void) {
  strcpy(global_wide, "a");
}
