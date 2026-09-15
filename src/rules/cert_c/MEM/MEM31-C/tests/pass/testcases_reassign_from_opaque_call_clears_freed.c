/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Companion to tests/pass/testcases_wrapper_reassign_after_free.c, which
 * covers the case where FunctionSummary CAN see the wrapper's body and
 * recognize it as an allocator. Here it cannot: the reassignment reads
 * through a declaration whose definition is not in the scan, and through a
 * struct field. Neither is a recognized allocation, a bare identifier or
 * NULL -- the three right-hand sides that used to clear freed-state -- so
 * the freed mark from the earlier free() survived and the later free() read
 * as a double free.
 *
 * It is the assignment itself that makes the mark meaningless: whatever the
 * name holds afterwards, it is not the pointer that was freed. curl hits
 * both shapes -- lib/netrc.c's `curlx_free(login); login = curlx_strdup(tok);`
 * (curlx_strdup is a macro, so no summary exists to rescue it, and it misses
 * the `_dup` suffix heuristic by an underscore) and lib/sendf.c's
 * `curlx_free(writer); writer = data->req.writer_stack;` inside a loop.
 */

#include <stdlib.h>

struct queue {
    char *head;
};

/* Definition deliberately absent from the scan. */
char *opaque_dup(const char *s);

void reassign_from_opaque_wrapper(const char *tok) {
    char *login = malloc(16);

    free(login);

    /* Fresh block from a callee this rule cannot see into. */
    login = opaque_dup(tok);

    /* Frees the NEW block, not the one released above. */
    free(login);
}

void reassign_from_field_in_loop(struct queue *q) {
    char *item = q->head;

    while (item) {
        q->head = NULL;
        free(item);
        /* Next iteration works on a different block. */
        item = q->head;
    }
}
