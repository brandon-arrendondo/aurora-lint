/*
 * Rule: API00-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * A hosted environment guarantees that main's argv is a non-null array of
 * argc + 1 pointers (C11 5.1.2.2.1p2), so main has nothing to validate. The
 * strict preset declares a freestanding environment, where that guarantee
 * does not exist and main is an ordinary function whose pointer parameter
 * arrives unchecked.
 */
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        return 1;
    }
    return (int)strlen(argv[1]);
}
