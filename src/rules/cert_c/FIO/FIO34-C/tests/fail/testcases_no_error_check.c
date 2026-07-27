/*
 * Rule: FIO34-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO34-C violation. A getchar() loop
 * comparing to EOF with no feof()/ferror() verification AND no
 * static_assert(UCHAR_MAX < UINT_MAX, ...) compile-time guarantee is
 * genuinely noncompliant -- this matches CERT's own bare "Noncompliant
 * Code Example" exactly (verified against the live wiki). Only one of
 * the two disambiguation strategies (runtime feof/ferror, or compile-time
 * static_assert per the "Compliant Solution (Nonportable)" section) makes
 * this compliant; this fixture has neither.
 */

#include <stdio.h>

int main() {
    int c;

    printf("Reading input without error checking:\n");

    // VIOLATION: Doesn't check ferror() for I/O errors vs EOF
    while ((c = getchar()) != EOF) {
        printf("Character: %c\n", c);
    }

    // Assumes EOF always means end of input, not I/O error
    printf("Reading completed\n");
    return 0;
}