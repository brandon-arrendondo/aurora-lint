/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: The old rule reported every allocation. A buffer that reaches no credential sink is not shown to hold a secret, whatever it is called.
 */

#include <stdlib.h>
#include <string.h>

size_t copy_secret_name(const char *name) {
    char *secret = (char *)malloc(64);
    size_t n;
    if (secret == NULL) return 0;
    strncpy(secret, name, 63);
    secret[63] = '\0';
    n = strlen(secret);
    free(secret);
    return n;
}
