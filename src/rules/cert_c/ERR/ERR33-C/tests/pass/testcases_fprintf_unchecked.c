/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: fprintf() return value is not checked for write errors
 */

#include <stdio.h>

int main() {
    FILE *file = fopen("log.txt", "w");
    if (file == NULL) {
        return 1;
    }

    // VIOLATION: Return value not checked
    fprintf(file, "Log entry: %d\n", 123);

    // Assuming write succeeded
    printf("Log entry supposedly written\n");

    // Another unchecked fprintf
    fprintf(file, "Another entry: %s\n", "test");

    if (fclose(file) != 0) {
        return 1;
    }
    return 0;
}