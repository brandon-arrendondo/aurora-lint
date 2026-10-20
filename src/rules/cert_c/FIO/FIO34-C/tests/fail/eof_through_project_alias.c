/*
 * Rule: FIO34-C
 * Source: aurora-lint
 * Status: FAIL - getc() is stored in a char and compared with EOF through a
 * project alias of it
 *
 * `MY_EOF` is defined as EOF itself, so the loop compares with EOF even
 * though the token is spelled differently.
 */
#include <stdio.h>

#define MY_EOF EOF

void copy_out(FILE *f) {
    char c;
    while ((c = getc(f)) != MY_EOF) {
        putchar(c);
    }
}
