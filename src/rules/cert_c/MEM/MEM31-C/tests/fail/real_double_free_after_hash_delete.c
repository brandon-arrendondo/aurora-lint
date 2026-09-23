/*
 * Rule: MEM31-C
 * Source: task_426
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: Unlinking with HASH_DELETE does not itself free anything, so the
 * genuine double free() below must still be detected (task 426).
 */

#define HASH_DELETE(hh, head, item) ((void)(hh), (void)(head), (void)(item))

struct entry {
    int hh;
};

void remove_and_double_free(struct entry *table, struct entry *item) {
    HASH_DELETE(hh, table, item);
    free(item);
    free(item);
}
