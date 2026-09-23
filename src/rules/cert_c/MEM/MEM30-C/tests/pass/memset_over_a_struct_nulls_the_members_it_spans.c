/* A memset over a struct overwrites the pointer members inside it, so a
 * member freed before it does not still hold the freed value afterwards.
 * Both spellings sqlite uses (aurora_lint 1446).
 *
 * Without the fix each function below reports: the first as a double free
 * of sOut.aBuf, the second as a use-after-free of pCsr->filter.zTerm and
 * of pCsr->zStop. */
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;

struct SessionBuffer {
  char *aBuf;
  int nBuf;
};

/* sqlite3session.c: the error path frees the buffer and zeroes the struct,
 * and the common exit path frees it again -- of a member the memset set to
 * NULL. */
int whole_object(int rc, void **ppOut) {
  struct SessionBuffer sOut;
  sOut.aBuf = malloc(32);
  sOut.nBuf = 32;
  if (rc != 0) {
    free(sOut.aBuf);
    memset(&sOut, 0, sizeof(sOut));
  }
  if (rc == 0 && ppOut) {
    *ppOut = (void *)sOut.aBuf;
    sOut.aBuf = 0;
  }
  free(sOut.aBuf);
  return rc;
}

struct AuxCursor {
  int csr;
  struct {
    char *zTerm;
    int nTerm;
  } filter;
  char *zStop;
};

/* fts3_aux.c: "in case this cursor is being reused, close and zero it" --
 * the memset runs from one member to one past the end of the object, so
 * every member freed above it reads NULL afterwards, not freed storage.
 * The destination (&pCsr->csr) does not contain the freed members, so only
 * the length tells us how far the write reached. */
int object_tail(struct AuxCursor *pCsr, int cond) {
  free((void *)pCsr->filter.zTerm);
  free(pCsr->zStop);
  memset(&pCsr->csr, 0, ((u8 *)&pCsr[1]) - (u8 *)&pCsr->csr);
  if (cond) {
    pCsr->filter.zTerm = malloc(8);
  }
  return use_two(pCsr->filter.zTerm, pCsr->zStop);
}
