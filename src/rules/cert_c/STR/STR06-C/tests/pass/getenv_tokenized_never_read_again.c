/*
 * Rule: STR06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger STR06-C violation
 * Description: The environment string is tokenized and never referred to
 * again, so nothing assumes strtok() left it unchanged. Modifying a getenv()
 * result is ENV30-C's construct; STR06-C's violation is a later use of the
 * tokenized string (STR06-C/2026-10-07/1), and there is none here.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void parse_path(void) {
    char *path = getenv("PATH");
    char *tok = strtok(path, ":");
    while (tok != NULL) {
        puts(tok);
        tok = strtok(NULL, ":");
    }
}
