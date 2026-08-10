#include <stdio.h>

/* task 413: open/close tracking must not leak across functions. Both
 * functions use a local FILE* named `fp` and open the same filename;
 * since these are unrelated local variables in separate functions,
 * this must NOT be reported as "file already open". */

void functionA(void) {
    FILE *fp = fopen("data.txt", "r");
    /* fp intentionally left open at the end of this function: the
     * regression is that a *later* function's fopen() of the same
     * filename/variable name got misreported as reopening this one. */
    if (fp) {
        fprintf(fp, "hello");
    }
}

void functionB(void) {
    FILE *fp = fopen("data.txt", "r");
    if (fp) {
        fclose(fp);
    }
}
