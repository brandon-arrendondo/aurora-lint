/*
 * Rule: API00-C
 * Source: synthetic
 * Status: PASS under every preset
 * Expect: default=clean strict=clean pedantic=clean
 *
 * A hosted environment guarantees that main's argv is a non-null array of
 * argc + 1 pointers (C11 5.1.2.2.1p2), so main has nothing to validate.
 * Every preset is hosted. A project that declares a freestanding
 * environment loses the guarantee (main_argv_guarantees), and main becomes an
 * ordinary function whose pointer parameter arrives unchecked.
 */
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        return 1;
    }
    return (int)strlen(argv[1]);
}
