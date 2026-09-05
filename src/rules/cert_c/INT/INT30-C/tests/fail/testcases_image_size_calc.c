// sqc-test: prescan
// Needs the project context a real scan builds: the INT3x provenance gate
// runs in every configuration now, and without context it has no summaries
// to resolve this file's own callees against.
/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Image buffer size calculation with multiplication wrap
 */

#include <stdlib.h>

void allocate_image(unsigned int width, unsigned int height, unsigned int bpp) {
    // Multiplication may wrap - common vulnerability in image processing
    size_t buffer_size = width * height * (bpp / 8);  // Line 10 - VIOLATION

    unsigned char *image = malloc(buffer_size);
    if (image) {
        free(image);
    }
}

int main(void) {
    allocate_image(65536, 65536, 32);  // Will wrap
    return 0;
}
