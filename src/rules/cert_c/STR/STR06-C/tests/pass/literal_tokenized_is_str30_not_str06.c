/*
 * Rule: STR06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger STR06-C violation
 * Description: strtok() on a string literal is undefined behavior, but it is
 * STR30-C's construct (modifying a literal), not STR06-C's: no later use of
 * the parse string assumes it is unchanged.
 */

#include <string.h>
#include <stdio.h>

void tokenize_literal(void) {
    char *tok = strtok("one,two,three", ",");
    while (tok != NULL) {
        puts(tok);
        tok = strtok(NULL, ",");
    }
}
