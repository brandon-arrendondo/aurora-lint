/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: NULL-terminated pointer-array scans (argv/environ style) and an
 *         explicit end-pointer stop. Both bound the walk without any
 *         relational size comparison.
 */

#include <stddef.h>

int count_nonempty_args(char **argv) {
    char **p = argv;
    int n = 0;
    while (p != NULL && *p != NULL) {
        if (**p != '\0') {
            n++;
        }
        p++;
    }
    return n;
}

int count_env_truthiness(char **environ) {
    char **e = environ;
    int n = 0;
    while (*e) {
        if (**e == 'P') {
            n++;
        }
        e++;
    }
    return n;
}

int sum_until_end_pointer(const char *filepnt, const char *fileend) {
    int sum = 0;
    while (filepnt != fileend) {
        sum += *filepnt;
        filepnt++;
    }
    return sum;
}
