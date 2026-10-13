/*
 * Rule: CON33-C
 * Source: testcases
 * Status: FAIL - Should trigger CON33-C violation
 *
 * A macro that names the library function in its own replacement list still
 * calls that function: the preprocessor does not expand a macro inside its
 * own replacement. The counting strtok is still the library's strtok.
 */

#include <string.h>

extern unsigned long tokenize_calls;

#define strtok(s, d) (tokenize_calls++, strtok(s, d))

char *first_word(char *line) { return strtok(line, " "); }
