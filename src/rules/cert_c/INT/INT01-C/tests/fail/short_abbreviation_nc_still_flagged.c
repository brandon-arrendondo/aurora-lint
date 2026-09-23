/*
 * Rule: INT01-C
 * Source: real-world (recall-preservation guard: 2-letter Hungarian
 *   abbreviations like nc/nb, as used in sqlite's ext/misc/base64.c, must
 *   still be flagged)
 * Status: FAIL - Should trigger INT01-C violation
 */
#include <stddef.h>

void *sqlite3_malloc(int n);

char *encode(int nc) {
  char *cBuf = (char *)sqlite3_malloc(nc);
  return cBuf;
}
