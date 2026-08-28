/*
 * Rule: MSC23-C
 * Source: task 347 (regression test)
 * Status: FAIL - the same byte-counting pattern as the wiki example, but
 * using getc() with an assigned read and an explicit break rather than
 * fgetc() in a feof()/ferror() loop, to check the detection isn't tied to
 * one specific loop/function spelling.
 */

#include <stdio.h>

long count_bytes(const char *path) {
    FILE *fp = fopen(path, "r");
    long total = 0;
    int ch;
    if (fp == 0) {
        return -1;
    }
    while (1) {
        ch = getc(fp);
        if (ch == EOF) {
            break;
        }
        total++;
    }
    fclose(fp);
    return total;
}
