/*
 * Rule: STR31-C
 * Source: testcases
 * Status: FAIL - Should trigger STR31-C violation
 */

/*
 * Rule: STR31-C - Guarantee that storage for strings has sufficient space for character data and the null terminator
 * Status: FAIL
 * Reason: Allocated memory is insufficient for the string being copied
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
// SQC-SUPPRESS: DCL00-C HASH:4b06527357a82ef1 JUSTIFICATION: "Test fixture: suppress co-firing rule"
    char source[] = "This string is too long for allocation";
    char *dest = malloc(10);  // Only 10 bytes allocated

    if (dest) {
        strcpy(dest, source);  // Source needs 39 bytes, buffer only has 10
        printf("Copied: %s\n", dest);
        free(dest);
    }

    return 0;
}
