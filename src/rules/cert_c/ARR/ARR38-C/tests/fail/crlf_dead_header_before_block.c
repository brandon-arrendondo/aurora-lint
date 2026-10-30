#include <string.h>
int f(char *d, const char *s, int x, int z, int n)
{
#if 0
  if (x) {
    n = 0;
  } else if (z)
#endif
  {
    memcpy(d, s, n); /* Expect: here */
  }
  return n;
}

/*
 * Rule: ARR38-C
 *
 * This file has Windows (CRLF) line endings, and .gitattributes keeps them.
 * The `#if 0` block holds the only header of the brace block after it, so
 * the parser is shown the block alone and the copy in it stays live. The
 * repair pass places that edit by byte offset, so it must count each line's
 * '\r'. One byte short per line, it blanked code a few bytes above the
 * directives and the whole function was lost, on this file and only as
 * CRLF. The code comes first, and this note last, so that a miscount lands
 * on code rather than on a leading comment.
 */
