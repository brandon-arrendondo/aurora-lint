/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `free(p); p = NULL;` is the idiom this rule's own suggestion
 * text recommends, and a later `free(p)` is `free(NULL)`, which does
 * nothing. None of these is a double free or a leak: the plain re-free, the
 * guarded re-free, the cleanup label reached by a goto that freed and
 * nulled first, and a local that is freed, nulled and never touched again.
 * The rule once kept the freed mark across `p = NULL`, so every one of
 * these read as a double free -- contradicting its own advice.
 */

#include <stdlib.h>

void refree(char *p) {
    free(p);
    p = NULL;
    free(p);
}

void guarded_refree(char *p) {
    free(p);
    p = NULL;
    if (p) free(p);
}

int cleanup_label(int c) {
    char *p = malloc(8);
    if (!p) return -1;
    if (c == 1) {
        free(p);
        p = NULL;
        goto out;
    }
    if (c == 2) goto out;
    free(p);
    return 0;
out:
    if (p) free(p);
    return 1;
}

void local_freed_then_nulled(void) {
    char *p = malloc(8);
    free(p);
    p = NULL;
}
