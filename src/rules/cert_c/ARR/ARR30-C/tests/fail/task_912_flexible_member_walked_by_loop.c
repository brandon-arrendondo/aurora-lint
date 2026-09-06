/*
 * Rule: ARR30-C
 * Source: task 912
 * Status: FAIL - SHOULD trigger ARR30-C violation
 * Reason: the counterpart to task_912_flexible_member_unrelated_loop.c --
 *         requiring the member name must not switch the check off. Here the
 *         loop really does walk the flexible array member, which is the
 *         pattern the check exists to report.
 */

#define FLEXARRAY 1

struct Fts5Structure {
    int nRef;
    int nLevel;
    int aLevel[FLEXARRAY];
};

void walk_member(struct Fts5Structure *p, int limit) {
    while (p->aLevel[0]++ < limit) {
        p->nRef++;
    }
}
