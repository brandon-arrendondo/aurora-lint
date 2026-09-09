/*
 * Rule: MEM31-C
 * Source: task 1092
 * Status: PASS - a locally-defined helper that only exits ends the path
 *
 * Task 1076 taught the tool about a noreturn helper *declared* with an
 * attribute. pure-ftpd's pure-pw.c defines its own `no_mem()` with no
 * attribute anywhere, so the free before the call looked like it fell through
 * into the `err:` label's second free.
 */

#include <stdio.h>
#include <stdlib.h>

static void no_mem(void)
{
    fprintf(stderr, "Out of memory\n");
    exit(1);
}

int build_db(const char *path)
{
    char *index_dbfile = malloc(16);
    char *data_dbfile;
    int ret = -1;
    FILE *fp = fopen(path, "r");

    if (fp == NULL) {
        free(index_dbfile);
        return -1;
    }
    if ((data_dbfile = malloc(16)) == NULL) {
        fclose(fp);
        free(index_dbfile);
        no_mem();
    }
    if (fputs("x", fp) < 0) {
        goto err;
    }
    ret = 0;
    err:
    free(index_dbfile);
    free(data_dbfile);
    fclose(fp);
    return ret;
}
