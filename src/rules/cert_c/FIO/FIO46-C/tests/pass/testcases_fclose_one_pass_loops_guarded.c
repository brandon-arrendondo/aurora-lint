/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - one-pass loops whose counter nothing else writes: a switch of the body's own, a macro that does not name the counter, a plain typedef
 */
#include <stdio.h>

#include <stddef.h>

#define LOG_ONCE() fputs("once\n", stderr)

typedef int count_t;

void own_switch(FILE *fp, int x) {
    int k;
    for (k = 0; k < 1; k++) {
        switch (x) {
        case 1:
            fclose(fp);
            break;
        default:
            break;
        }
    }
}

void unrelated_macro(FILE *fp) {
    int k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
        LOG_ONCE();
    }
}

void plain_typedef(FILE *fp) {
    count_t k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
    }
}

void standard_typedef(FILE *fp) {
    size_t k;
    for (k = 0; k < 1; k++) {
        fclose(fp);
    }
}
