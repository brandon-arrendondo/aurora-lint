/*
 * Rule: API00-C
 * Source: synthetic
 * Status: VIOLATION when the environment's main_argv_guarantees is withdrawn
 * Settings: main_argv_guarantees=false
 *
 * The same main as the pass fixture main_argv_needs_hosted_guarantee.c, in an
 * environment that does not guarantee main's argv (C11 5.1.2.2.1p2 binds
 * hosted implementations only): argv is an ordinary pointer parameter that
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
