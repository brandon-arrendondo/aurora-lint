/* A free and a status-variable assignment sitting side by side in a branch
 * whose own guard is not a constant comparison (so it yields no EqPred of
 * its own) still establish a fact about that status variable for the rest
 * of the branch. A later `if (rc == SUCCESS)` is an EqPred, and disjoint
 * from it, so the object freed alongside `rc = FAILURE` is not freed on
 * the path that reaches the guarded block (aurora_lint 1461).
 *
 * sqlite ext/fts3/fts3_write.c's fts3PendingListAppend caller is the case
 * this came from: a nested pointer-identity `if` frees `pList` and sets
 * `rc = SQLITE_NOMEM` as sibling statements, and a later `if (rc ==
 * SQLITE_OK)` reads `pList` again -- unreachable from the free. */
#include <stdlib.h>

#define SQLITE_OK 0
#define SQLITE_NOMEM 7

typedef struct { int nData; } PendingList;

PendingList *rehash(PendingList *p);
void use(PendingList *p);

int append_term(PendingList *pList) {
  int rc = SQLITE_OK;

  if (pList == rehash(pList)) {
    free(pList);
    rc = SQLITE_NOMEM;
  }

  if (rc == SQLITE_OK) {
    use(pList);
  }
  return rc;
}
