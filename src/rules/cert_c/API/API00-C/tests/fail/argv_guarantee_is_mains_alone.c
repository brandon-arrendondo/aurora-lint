/*
 * Rule: API00-C
 * Source: synthetic
 * Status: FAIL under every preset
 *
 * The hosted guarantee on argv (C11 5.1.2.2.1p2) binds only main's own
 * parameters. A function that merely takes the same shape receives
 * whatever its caller passes.
 */
#include <string.h>

int tool_main(int argc, char **argv)
{
    if (argc < 2) {
        return 1;
    }
    return (int)strlen(argv[1]);
}
