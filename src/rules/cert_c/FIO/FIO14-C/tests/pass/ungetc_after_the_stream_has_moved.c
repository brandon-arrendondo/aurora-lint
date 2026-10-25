/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO14-C violation
 * Settings: posix_version=none
 * Expect: default=clean strict=clean pedantic=clean
 *
 * ungetc() where the file position is not known to be 0: after a read or a
 * seek, in a loop whose earlier pass read the stream, on an append-mode or
 * unknown stream, or pushing back EOF, which leaves the stream unchanged.
 */
#include <stdio.h>

void push_back_after_a_read(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        int c = fgetc(fp);
        ungetc(c, fp);
        fclose(fp);
    }
}

void push_back_what_the_argument_reads(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        ungetc(fgetc(fp), fp);
        fclose(fp);
    }
}

void push_back_after_a_seek(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        fseek(fp, 4, SEEK_SET);
        ungetc('x', fp);
        fclose(fp);
    }
}

void push_back_in_a_loop_that_reads(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp == NULL) {
        return;
    }
    for (int i = 0; i < 4; i++) {
        ungetc('x', fp);
        (void)fgetc(fp);
    }
    fclose(fp);
}

void push_back_onto_append_stream(void) {
    FILE *fp = fopen("log.bin", "a+b");
    if (fp != NULL) {
        ungetc('x', fp);
        fclose(fp);
    }
}

void push_back_onto_unknown_stream(FILE *fp) {
    ungetc('x', fp);
}

void push_back_onto_stream_opened_on_one_branch(int which) {
    FILE *fp = stdin;
    if (which) {
        fp = fopen("data.bin", "rb");
    }
    ungetc('x', fp);
}

void push_back_eof(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        ungetc(EOF, fp);
        fclose(fp);
    }
}
