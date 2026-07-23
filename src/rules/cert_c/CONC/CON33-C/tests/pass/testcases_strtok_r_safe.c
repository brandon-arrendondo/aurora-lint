/*
 * Rule: CON33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON33-C violation
 *
 * Thread-safe strtok_r() usage
 */

#include <string.h>

void parse_tokens_safe(char *input) {
    char *saveptr;
    /* COMPLIANT: strtok_r is thread-safe */
    char *token = strtok_r(input, ",", &saveptr);
    while (token != NULL) {
        token = strtok_r(NULL, ",", &saveptr);
    }
}
