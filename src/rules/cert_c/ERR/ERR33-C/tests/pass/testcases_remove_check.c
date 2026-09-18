/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: PASS
 * Reason: remove() return value is properly checked for file deletion errors
 */

#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *filename = "test_file_to_remove.txt";

    // Create a test file first
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Failed to create test file\n");
        return 1;
    }

    if (fprintf(file, "Test content\n") < 0) {
        fprintf(stderr, "Failed to write to test file\n");
        (void)fclose(file);
        return 1;
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "Failed to close test file\n");
        return 1;
    }

    // Now try to remove the file
    if (remove(filename) != 0) {
        fprintf(stderr, "Failed to remove file: %s\n", filename);
        return 1;
    }

    printf("File removed successfully\n");
    return 0;
}