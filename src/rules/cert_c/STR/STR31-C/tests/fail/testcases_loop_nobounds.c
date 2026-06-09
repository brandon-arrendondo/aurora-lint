/*
 * Rule: STR31-C
 * Source: testcases
 * Status: FAIL - Should trigger STR31-C violation
 */

/*
 * Rule: STR31-C - Guarantee that storage for strings has sufficient space for character data and the null terminator
 * Status: FAIL
 * Reason: Manual string copy without bounds checking can overflow buffer
 */

#include <stdio.h>

int main() {
    char source[] = "This is a very long string that will overflow";
    char dest[10];
    int i = 0;

    // Copy without bounds checking
// SQC-SUPPRESS: ARR30-C HASH:830d8085a5fa29c4 JUSTIFICATION: "Test fixture: suppress co-firing rule"
    while (source[i] != '\0') {
        dest[i] = source[i];  // Buffer overflow when i >= 10
        i++;
    }
    dest[i] = '\0';

    printf("Copied: %s\n", dest);

    return 0;
}
