/*
 * Rule: MSC13-C
 * Status: PASS - option_index is read by getopt_long, the operand the
 * default build compiles (NO_GETOPT_LONG undefined) inside the while
 * condition's #ifndef/#else. The declaration sits under the same #ifndef,
 * so the two agree: the value is read, not dead.
 */

#include <getopt.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    int fodder;
#ifndef NO_GETOPT_LONG
    int option_index = 0;
    static struct option long_options[] = {
        {"help", 0, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
#endif

    while ((fodder =
#ifndef NO_GETOPT_LONG
            getopt_long(argc, argv, "h", long_options, &option_index)
#else
            getopt(argc, argv, "h")
#endif
            ) != -1) {
        if (fodder == 'h') {
            puts("help");
        }
    }
    return 0;
}
