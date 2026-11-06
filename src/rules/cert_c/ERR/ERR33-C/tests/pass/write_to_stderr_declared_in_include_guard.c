/*
 * Rule: ERR33-C
 * Source: synthetic
 * Status: PASS - The stream is the file-scope extern stderr, declared in a guard
 *
 * `stderr` is declared `extern` inside the include guard, outside any
 * function, so it is the standard error stream, the same as with no guard
 * around the file.
 */

#ifndef LOG_H
#define LOG_H

typedef struct stream FILE;
extern FILE *stderr;
int fprintf(FILE *stream, const char *format, ...);
int fputs(const char *s, FILE *stream);

void report(void)
{
    fprintf(stderr, "failed\n");
    fputs("failed\n", stderr);
}

#endif
