/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: setvbuf() return value is not checked for failure (non-zero)
 */

#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *file = fopen("output.txt", "w");
    if (file == NULL) {
        return 1;
    }

    char buffer[BUFSIZ];

    // VIOLATION: Return value not checked
    setvbuf(file, buffer, _IOFBF, BUFSIZ);

    printf("Buffer supposedly set\n");

    fprintf(file, "Test data\n");

    // Another unchecked setvbuf
    setvbuf(file, NULL, _IONBF, 0);
    printf("No buffering supposedly set\n");

    if (fclose(file) != 0) {
        return 1;
    }
    return 0;
}