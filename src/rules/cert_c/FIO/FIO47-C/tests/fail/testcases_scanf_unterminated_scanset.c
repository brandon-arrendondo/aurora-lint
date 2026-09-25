/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: FAIL - a scanf scanset that never reaches its closing ']' is not a
 * valid conversion specification.
 */

#include <stdio.h>

void read_unterminated(const char *text) {
    char word[32];

    sscanf(text, "%[abc", word);
}
