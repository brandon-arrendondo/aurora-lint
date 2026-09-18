/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: PASS
 * Reason: tmpfile() return value is properly checked for failure
 */

#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        fprintf(stderr, "Failed to create temporary file\n");
        return 1;
    }

    // Write to temporary file
    if (fprintf(temp_file, "Temporary data\n") < 0) {
        fprintf(stderr, "Failed to write to temporary file\n");
        (void)fclose(temp_file);
        return 1;
    }

    // Rewind and read from temporary file
    rewind(temp_file);
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), temp_file) != NULL) {
        printf("Read from temp file: %s", buffer);
    } else {
        fprintf(stderr, "Failed to read from temporary file\n");
    }

    if (fclose(temp_file) != 0) {
        fprintf(stderr, "Failed to close temporary file\n");
        return 1;
    }

    return 0;
}