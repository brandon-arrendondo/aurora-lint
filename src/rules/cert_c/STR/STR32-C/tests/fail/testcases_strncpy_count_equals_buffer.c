/*
 * Rule: STR32-C
 * Source: testcases
 * Status: FAIL - Should trigger STR32-C violation
 */

/*
 * Rule: STR32-C - Do not pass a non-null-terminated character sequence to a library function that expects a string
 * Status: FAIL
 * Reason: strncpy may not null-terminate if source length equals or exceeds count
 */

#include <stdio.h>
#include <string.h>

int main() {
    char source[] = "Exactly10!";  // 10 characters
    char dest[10];

    strncpy(dest, source, 10);  // No space for null terminator
    // dest is not null-terminated!
    printf("Copied: %s\n", dest);  // Undefined behavior

    return 0;
}