/*
 * Rule: STR11-C
 * Source: testcases
 * Status: PASS - Should NOT trigger STR11-C violation
 *
 * Each bound is larger than the literal with its terminator (EX2) once the
 * literal is measured as the compiler lays it out: a wide literal counts
 * characters, not bytes; octal and hexadecimal escapes are one element
 * each; a u8 literal counts its bytes.
 */
#include <wchar.h>

wchar_t wide[5] = L"abc";
char utf8[6] = u8"abc";
char octal[6] = "\101\102\103";
char hex[3] = "\x41";
char joined[8] = "ab" "cd";
const char *names[3] = {"a", "bb", "ccc"};
