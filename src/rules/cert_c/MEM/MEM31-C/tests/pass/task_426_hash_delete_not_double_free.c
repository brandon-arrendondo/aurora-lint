/*
 * Rule: MEM31-C
 * Source: task_426
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: HASH_DELETE/DL_DELETE (uthash/utlist) only unlink an entry from a
 * hash table or linked list -- they never call free(). The immediately
 * following free() call is the only free of this memory and must not be
 * flagged as a double free (task 426).
 */

#define HASH_DELETE(hh, head, item) ((void)(hh), (void)(head), (void)(item))
#define DL_DELETE(head, item) ((void)(head), (void)(item))

struct entry {
    int hh;
    struct entry *next;
};

void remove_shared(struct entry *table, struct entry *item) {
    HASH_DELETE(hh, table, item);
    free(item);
}

void remove_from_list(struct entry *head, struct entry *item) {
    DL_DELETE(head, item);
    free(item);
}
