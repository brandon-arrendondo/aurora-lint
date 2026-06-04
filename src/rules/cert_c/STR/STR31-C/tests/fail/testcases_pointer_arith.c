/*
 * Rule: STR31-C
 * Source: testcases
 * Status: FAIL - Should trigger STR31-C violation
 */

/*
 * Rule: STR31-C - Guarantee that storage for strings has sufficient space for character data and the null terminator
 * Status: FAIL
 * Reason: Pointer arithmetic can write beyond allocated buffer bounds
 */

#include <stdio.h>
#include <stdlib.h>

int main() {
    char *buffer = malloc(10);
    char *ptr = buffer;
    char data[] = "This string is much too long for the buffer";
    int i = 0;

// SQC-SUPPRESS: ARR30-C HASH:57e52963cf44ee2b JUSTIFICATION: "Test fixture: suppress co-firing rule"
    while (data[i] != '\0') {
// SQC-SUPPRESS: ARR30-C HASH:8c037058a81106ed JUSTIFICATION: "Test fixture: suppress co-firing rule"
        *ptr++ = data[i++];  // Writes beyond allocated 10 bytes
    }
    *ptr = '\0';

    printf("Copied: %s\n", buffer);
    free(buffer);

    return 0;
}
