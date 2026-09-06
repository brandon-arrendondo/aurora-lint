/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: Three more terminator-bounded walk spellings that are not a size
 *         comparison. A macro-named NUL (`#define EOS '\0'`) is the sentinel
 *         just as `0` is; `while (*p == '-')` continues only while the pointee
 *         equals a non-NUL constant, so the terminator stops it; and a
 *         producer loop stops on the call's NULL return.
 */

#include <stdio.h>

#define EOS '\0'

int count_digits(const char *s) {
    const char *p = s;
    int n = 0;
    while (*p != EOS) {
        if (*p >= '0' && *p <= '9') {
            n++;
        }
        p++;
    }
    return n;
}

const char *skip_dashes(const char *arg) {
    while (*arg == '-') {
        if (*arg == 0) {
            break;
        }
        arg++;
    }
    return arg;
}

int count_hashes(FILE *fp) {
    char line[128];
    int n = 0;
    while (fgets(line, 128, fp) != NULL) {
        char *p = line;
        if (*p == '#') {
            n++;
        }
        p++;
    }
    return n;
}
