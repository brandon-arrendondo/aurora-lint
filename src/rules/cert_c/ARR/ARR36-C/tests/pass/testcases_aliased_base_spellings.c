/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to the same array
 * Status: PASS
 * Reason: One base reached under two spellings. Every pointer below provably
 *         derives from a single object; the rule must not report a base as
 *         differing from itself because one path spelled it as the raw
 *         identifier and another as the tracked base.
 *
 *         Distilled from curl lib/mprintf.c (out_number) and sqlite
 *         src/btree.c (rebuildPage) / src/vdbe.c.
 */

#include <stddef.h>
#include <stdio.h>

struct page {
    unsigned char *data;
    int used;
};

/* A parameter records its base as "param:work"; `&work[N]` used to record the
 * raw "work", so `w >= work` compared one buffer against itself. */
void number_into(char *work, int prec) {
    char *workend = &work[64 - 2];
    char *w = workend;

    while (prec-- > 0 && w >= work) {
        *w-- = '0';
    }

    printf("%td\n", workend - w);
}

/* A local aliasing a member records its base as "p->data"; `&data[n]` used to
 * record the raw "data", so `end - data` compared one buffer against itself. */
size_t page_used(struct page *p, int usable) {
    unsigned char *const data = p->data;
    unsigned char *const end = &data[usable];
    unsigned char *cur;

    cur = end;
    while (cur > data) {
        cur--;
    }

    if (cur < end) {
        printf("scanned\n");
    }
    return (size_t)(end - data);
}

int main(void) {
    char buf[64] = {0};
    unsigned char raw[32] = {0};
    struct page pg;

    pg.data = raw;
    pg.used = 32;

    number_into(buf, 4);
    printf("%zu\n", page_used(&pg, 32));
    return 0;
}
