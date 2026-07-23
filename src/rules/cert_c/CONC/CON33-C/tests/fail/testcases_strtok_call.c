/*
 * Rule: CON33-C
 * Source: testcases
 * Status: FAIL - Should trigger CON33-C violation
 *
 * Non-thread-safe strtok() usage
 */

#include <string.h>

void parse_tokens(char *input) {
    /* VIOLATION: strtok is not thread-safe */
    char *token = strtok(input, ",");
    while (token != NULL) {
        token = strtok(NULL, ",");
    }
}
