/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO14-C violation
 * Expect: default=violation strict=violation pedantic=violation
 *
 * ungetc() on a stream nothing has read or positioned since it was opened:
 * the file position is 0 before the call, so it is indeterminate after it
 * for a binary stream (C11 7.21.7.10p5), unspecified for a text stream, and
 * unspecified for every stream under POSIX. The default preset assumes
 * POSIX and still reports it.
 */
#include <stdio.h>

void push_back_onto_new_binary_stream(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        ungetc('x', fp);
        fclose(fp);
    }
}

void push_back_onto_new_text_stream(void) {
    FILE *fp;
    if ((fp = fopen("notes.txt", "r")) == NULL) {
        return;
    }
    ungetc('#', fp);
    fclose(fp);
}

void push_back_onto_reopened_stream(FILE *fp) {
    freopen("data.bin", "r+b", fp);
    if (fp) {
        ungetc('x', fp);
    }
}

void push_back_onto_stream_opened_by_fopen_s(const char *name) {
    FILE *fp = NULL;
    fopen_s(&fp, name, "rb");
    if (fp == NULL) {
        return;
    }
    ungetc('x', fp);
    fclose(fp);
}

static FILE *shared;

void push_back_onto_new_shared_stream(void) {
    shared = fopen("data.bin", "rb");
    if (shared != NULL) {
        ungetc('x', shared);
    }
}

void push_back_in_a_loop_that_never_reads(int tries) {
    FILE *fp = fopen("data.bin", "rb");
    while (tries > 0 && fp) {
        ungetc('x', fp);
        tries--;
    }
}
