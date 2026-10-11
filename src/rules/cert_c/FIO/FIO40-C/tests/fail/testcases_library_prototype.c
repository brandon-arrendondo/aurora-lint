/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO40-C violation
 *
 * A plain prototype of fgets declares the library function, not one of the
 * file's own, so the call is the library read and its failure path is
 * checked: the buffer is read after the failed call.
 */

typedef struct _IO_FILE FILE;
extern FILE *stdin;
char *fgets(char *, int, FILE *);
int puts(const char *);

void echo(void) {
    char buf[64];
    if (fgets(buf, sizeof buf, stdin) == 0) {
        puts("read failed");
    }
    puts(buf);
}
