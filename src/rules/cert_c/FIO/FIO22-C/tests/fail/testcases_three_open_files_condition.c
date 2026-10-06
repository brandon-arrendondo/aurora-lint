/*
 * Rule: FIO22-C
 * Description: Three files open when a process is spawned from a condition; the finding names all three, in name order
 * Status: FAIL - Should trigger FIO22-C violation
 */

#include <stdio.h>
#include <stdlib.h>

int archive(const char *a, const char *b, const char *c) {
    FILE *out = fopen(a, "w");
    FILE *in = fopen(b, "r");
    FILE *errs = fopen(c, "a");
    if (out == NULL || in == NULL || errs == NULL) {
        return -1;
    }
    if (system("tar -cf backup.tar data") != 0) {
        return -1;
    }
    fclose(errs);
    fclose(in);
    fclose(out);
    return 0;
}
