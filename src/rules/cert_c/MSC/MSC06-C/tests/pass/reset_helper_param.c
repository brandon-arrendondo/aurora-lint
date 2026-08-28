/*
 * Rule: MSC06-C
 * Source: task 565 (fts5SegIterClear-style clear/reset helper)
 * Status: PASS - pIter is a caller-owned pointer parameter; the struct it
 * points to persists past this call, so it never goes out of scope here.
 */

typedef struct Iter {
  char *buf;
  int len;
} Iter;

void freeBuf(char *b);

void iterClear(Iter *pIter) {
  freeBuf(pIter->buf);
  memset(pIter, 0, sizeof(*pIter));
}
