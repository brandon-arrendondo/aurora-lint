/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO40-C violation
 *
 * Freeing the buffer is not a read of its contents, and ends them: after a
 * failed read the buffer is only released, by free() or by a wrapper whose
 * body frees its argument. A helper whose body fills its argument writes
 * the buffer before anything reads it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void release(void *p) {
    free(p);
}

static void fill_default(char *dst) {
    strcpy(dst, "none");
}

void read_lines(FILE *fp, size_t n) {
    char *buf = malloc(n);
    if (buf == NULL) {
        return;
    }
    while (fgets(buf, (int) n, fp) != NULL) {
        fputs(buf, stdout);
    }
    free(buf);
}

void read_one(FILE *fp, size_t n) {
    char *buf = malloc(n);
    if (buf == NULL) {
        return;
    }
    if (fgets(buf, (int) n, fp) != NULL) {
        fputs(buf, stdout);
    }
    release(buf);
}

void read_or_default(FILE *fp) {
    char buf[32];
    if (fgets(buf, sizeof buf, fp) == NULL) {
        fill_default(buf);
    }
    puts(buf);
}
