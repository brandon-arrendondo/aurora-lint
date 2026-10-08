/*
 * Rule: MEM30-C
 * Source: real-world (sqlite ext/session/changeset.c:247-270, valkey
 *         src/valkey-benchmark.c:351/352/1835 -- adjudicated FP in run 267)
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * The branch frees `p` and then calls `fatal`, declared `_Noreturn` with no
 * body in view. The default and strict policies trust the keyword (C11
 * 6.7.4p8; CERT MSC37-C-EX2), so the branch has no join edge and the later
 * use and free are fine. The pedantic policy accepts only a body verified
 * never to return, so the freed `p` reaches the join and the later use reads
 * freed memory.
 */

#include <stdlib.h>

_Noreturn void fatal(const char *msg);
void use(char *p);

int declared_noreturn(int rc)
{
    char *p = malloc(16);
    if (rc != 0) {
        free(p);
        fatal("bad");
    }
    use(p);
    free(p);
    return 0;
}
